"""N threads x M requests through the proxy (keep-alive per thread); prints errors and timings."""
import http.client, ssl, sys, threading, time
proxy_host, proxy_port, target_host, target_port, scheme, threads, per = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5], int(sys.argv[6]), int(sys.argv[7])
errors, done = [], [0]
lock = threading.Lock()
def worker():
    ctx = ssl._create_unverified_context()
    conn = None
    for i in range(per):
        try:
            if conn is None:
                if scheme == "https":
                    conn = http.client.HTTPSConnection(proxy_host, proxy_port, context=ctx, timeout=30)
                    conn.set_tunnel(target_host, target_port)
                else:
                    conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=30)
            path = "/ok" if i % 10 else "/gzip"
            url = path if scheme == "https" else f"http://{target_host}:{target_port}{path}"
            conn.request("GET", url)
            r = conn.getresponse(); body = r.read()
            if r.status != 200 or not body:
                with lock: errors.append(f"{r.status} {len(body)}")
            with lock: done[0] += 1
        except Exception as e:
            with lock: errors.append(repr(e)[:100])
            conn = None
t = time.time()
ts = [threading.Thread(target=worker) for _ in range(threads)]
[x.start() for x in ts]; [x.join() for x in ts]
dt = time.time() - t
print(f"{scheme}: {done[0]} ok, {len(errors)} errors in {dt:.1f}s ({done[0]/dt:.0f} req/s)", errors[:5])
