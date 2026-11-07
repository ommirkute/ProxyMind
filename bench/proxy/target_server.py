"""Test target for the proxy matrix (bench/proxy/run.sh): plain HTTP on argv[1], HTTPS on argv[2]
with the certificate+key in argv[3]. Streaming, big, slow, keep-alive and edge-case endpoints."""
CONNS = 0
import http.server, socketserver, ssl, sys, time, threading, gzip, os

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 2  # idle keep-alive connections are closed after 2 s
    disable_nagle_algorithm = True
    def setup(self):
        global CONNS
        CONNS += 1
        super().setup()
    def log_message(self, *a): pass
    def send(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers: self.send_header(k, v)
        if code not in (204, 304) and self.command != "HEAD" or self.command == "HEAD":
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and code not in (204, 304): self.wfile.write(body)
    def do_HEAD(self): self.do_GET()
    def do_GET(self):
        p, _, q = self.path.partition("?")
        args = dict(x.split("=") for x in q.split("&") if "=" in x)
        if p == "/ok": return self.send(200, b"ok")
        if p == "/conns": return self.send(200, str(CONNS).encode())
        if p == "/sse":
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
            for i in range(int(args.get("n", 10))):
                d = f"data: tick {i}\n\n".encode(); self.wfile.write(b"%x\r\n%s\r\n" % (len(d), d)); self.wfile.flush(); time.sleep(float(args.get("gap", 0.5)))
            self.wfile.write(b"0\r\n\r\n"); return
        if p == "/big":
            n = int(args.get("mb", 10)) * 1024 * 1024
            self.send_response(200); self.send_header("Content-Length", str(n)); self.send_header("Content-Type", "application/octet-stream"); self.end_headers()
            chunk = b"x" * 65536; sent = 0
            while sent < n:
                k = min(len(chunk), n - sent); self.wfile.write(chunk[:k]); sent += k
            return
        if p == "/slow":
            time.sleep(float(args.get("s", 5))); return self.send(200, b"finally")
        if p == "/trickle":
            self.send_response(200); self.send_header("Transfer-Encoding", "chunked"); self.send_header("Trailer", "X-Done"); self.end_headers()
            for i in range(5): self.wfile.write(b"1\r\n%d\r\n" % i); self.wfile.flush(); time.sleep(0.2)
            self.wfile.write(b"0\r\nX-Done: yes\r\n\r\n"); return
        if p == "/gzip":
            body = gzip.compress(b"hello gzip " * 1000)
            return self.send(200, body, [("Content-Encoding", "gzip")])
        if p == "/204": return self.send(204)
        if p == "/304": return self.send(304, b"", [("ETag", '"x"')])
        if p == "/close":
            self.send_response(200); self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(b"until close"); self.close_connection = True; return
        if p == "/redirect": return self.send(302, b"", [("Location", "/ok")])
        if p == "/cookies": return self.send(200, b"c", [("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/; HttpOnly")])
        return self.send(404, b"nope")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); left = n; got = 0
        while left:
            b = self.rfile.read(min(left, 1 << 20)); got += len(b); left -= len(b)
            if not b: break
        return self.send(200, f"got {got}".encode())
    do_PUT = do_POST

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True; allow_reuse_address = True

http_port, https_port, cert = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
a = S(("127.0.0.1", http_port), H)
b = S(("127.0.0.1", https_port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, cert)
b.socket = ctx.wrap_socket(b.socket, server_side=True)
threading.Thread(target=a.serve_forever, daemon=True).start()
b.serve_forever()
