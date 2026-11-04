"""Runs real-world traffic patterns through the proxy and checks each.
usage: matrix.py <proxy host:port> <http port> <https port> <proxy CA pem> [case...]"""
import hashlib, subprocess, sys, time, os, tempfile

proxy, hp, sp, ca = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
only = set(sys.argv[5:])
results = []
FLAGS = []

def curl(url, *extra, via=True, timeout=120):
    args = ["curl", "-sS", "--max-time", str(timeout), "-o", "-", "-w", "\n%{http_code} %{time_starttransfer} %{time_total} %{size_download} %{num_connects}"]
    if via: args += ["-x", f"http://{proxy}", "--noproxy", "", "--cacert", ca]
    else: args += ["-k"]
    args += FLAGS + list(extra) + [url]
    env = {k: v for k, v in os.environ.items() if k.lower() not in ("no_proxy", "http_proxy", "https_proxy", "all_proxy")}
    p = subprocess.run(args, capture_output=True, env=env)
    out = p.stdout
    body, _, meta = out.rpartition(b"\n")
    parts = meta.decode().split()
    if len(parts) != 5: return None, body, p.stderr.decode()[:200]
    code, ttfb, total, size, conns = parts
    return dict(code=int(code), ttfb=float(ttfb), total=float(total), size=int(size), conns=int(conns)), body, p.stderr.decode()[:200]

def case(name, fn):
    if only and name not in only: return
    t = time.time()
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"error: {e}"
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} {name:<22} {detail}  ({time.time()-t:.1f}s)", flush=True)

for scheme, port, flags in (("http", hp, []), ("https", sp, []), ("https-h1", sp, ["--http1.1"])):
    FLAGS[:] = flags
    base = f"{scheme.split('-')[0]}://localhost:{port}"
    def sse():
        m, body, err = curl(base + "/sse?n=8&gap=0.5", "-N")
        return (m and m["code"] == 200 and m["ttfb"] < 1.0 and body.count(b"data: tick") == 8), f"{m} {err}"
    case(f"{scheme}-sse-streams", sse)
    def trickle():
        m, body, err = curl(base + "/trickle", "-N")
        return (m and m["ttfb"] < 0.6 and body == b"01234"), f"{m} body={body[:20]!r} {err}"
    case(f"{scheme}-chunked-trickle", trickle)
    def big():
        m, body, err = curl(base + "/big?mb=300", "-o", "/dev/null")
        return (m and m["code"] == 200 and m["size"] == 300 * 1024 * 1024), f"{m} {err}"
    case(f"{scheme}-download-300mb", big)
    def slow():
        m, body, err = curl(base + "/slow?s=70", timeout=100)
        return (m and m["code"] == 200 and body == b"finally"), f"{m} {err}"
    case(f"{scheme}-long-poll-70s", slow)
    def keepalive():
        urls = [base + "/ok"] * 40
        _, before, _ = curl(base + "/conns", via=False)
        t0 = time.time(); m, body, err = curl(urls[0], *urls[1:]); dt = time.time() - t0
        _, after, _ = curl(base + "/conns", via=False)
        opened = int(after) - int(before) - 1  # minus the direct /conns check
        return (body.count(b"ok") >= 40 and opened <= 2), f"40 requests in {dt:.2f}s over {opened} server connection(s) {err}"
    case(f"{scheme}-keepalive-40", keepalive)
    def stale():
        m1, b1, e1 = curl(base + "/ok")
        time.sleep(3)  # the server closes its idle connections after 2 s
        m2, b2, e2 = curl(base + "/ok")
        m3, b3, e3 = curl(base + "/upload", "-X", "POST", "--data-binary", "x")
        return (b1 == b"ok" and b2 == b"ok" and b3 == b"got 1"), f"{m2} {e2} {m3} {b3!r} {e3}"
    case(f"{scheme}-stale-connection", stale)
    def expect100():
        data = os.urandom(2 * 1024 * 1024)
        f = tempfile.NamedTemporaryFile(delete=False); f.write(data); f.close()
        m, body, err = curl(base + "/upload", "-X", "POST", "--data-binary", "@" + f.name, "-H", "Expect: 100-continue")
        os.unlink(f.name)
        return (m and body == b"got %d" % len(data) and m["total"] < 0.8), f"{m} {body[:30]!r} {err}"
    case(f"{scheme}-expect-100", expect100)
    def upload50():
        f = tempfile.NamedTemporaryFile(delete=False); f.write(b"u" * (50 << 20)); f.close()
        m, body, err = curl(base + "/upload", "-X", "PUT", "--data-binary", "@" + f.name, "-H", "Expect:")
        os.unlink(f.name)
        return (m and body == b"got %d" % (50 << 20)), f"{m} {body[:30]!r} {err}"
    case(f"{scheme}-upload-50mb", upload50)
    def misc():
        bad = []
        for path, code in (("/204", 204), ("/304", 304), ("/redirect", 302), ("/ok", 200)):
            m, body, err = curl(base + path, timeout=5)
            if not m or m["code"] != code or m["total"] > 2: bad.append(f"{path}:{m} {err}")
        m, body, err = curl(base + "/ok", "-I", timeout=5)
        if not m or m["code"] != 200 or m["total"] > 2: bad.append(f"HEAD:{m} {err}")
        m, body, err = curl(base + "/close", timeout=5)
        if not m or body != b"until close": bad.append(f"close:{m} {body!r}")
        return not bad, "; ".join(bad) or "204/304/302/HEAD/close fine"
    case(f"{scheme}-edge-statuses", misc)
    def gzip_exact():
        _, a, _ = curl(base + "/gzip")
        _, b, _ = curl(base + "/gzip", via=False)
        return a == b and len(a) > 0, f"via={hashlib.sha1(a).hexdigest()[:8]} direct={hashlib.sha1(b).hexdigest()[:8]}"
    case(f"{scheme}-gzip-byte-exact", gzip_exact)

failed = [r for r in results if not r[1]]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
