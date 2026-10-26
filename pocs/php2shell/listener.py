import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",9001)); s.listen(5)
print("[listener] waiting on 9001",flush=True)
while True:
    c,a=s.accept()
    data=c.recv(4096)
    print(f"[listener] CALLBACK from {a[0]}: {data.decode(errors='replace').strip()}",flush=True)
    c.close()
