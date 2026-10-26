import sys, socket, threading, time
HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv)>1 else 8090
THREADS = int(sys.argv[2]) if len(sys.argv)>2 else 15
DURATION = int(sys.argv[3]) if len(sys.argv)>3 else 220
stop = time.time() + DURATION
count = [0]*THREADS
def worker(i):
    while time.time() < stop:
        try:
            s = socket.create_connection((HOST,PORT),timeout=5)
            # each connection does a burst of keep-alive GETs then closes (simulates clients)
            for _ in range(20):
                if time.time()>=stop: break
                s.sendall(f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: keep-alive\r\n\r\n".encode())
                buf=b""
                while b"\r\n\r\n" not in buf:
                    c=s.recv(4096)
                    if not c: raise IOError
                    buf+=c
                # drain content-length
                cl=0
                for line in buf.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"): cl=int(line.split(b":")[1])
                body=buf.split(b"\r\n\r\n",1)[1]
                while len(body)<cl: 
                    c=s.recv(4096); 
                    if not c: break
                    body+=c
                count[i]+=1
            s.close()
        except Exception:
            time.sleep(0.01)
ts=[threading.Thread(target=worker,args=(i,),daemon=True) for i in range(THREADS)]
for t in ts: t.start()
for t in ts: t.join()
print(f"load done: {sum(count)} requests over {DURATION}s on :{PORT} with {THREADS} threads")
