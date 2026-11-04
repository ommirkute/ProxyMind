// A modern-looking HTTPS site over HTTP/2 (HTTP/1.1 too): many parallel
// assets, gzip, server-sent events, a big download and an upload by script.
import http2 from "node:http2";
import zlib from "node:zlib";
import { readFileSync } from "node:fs";
import https from "node:https";
import crypto from "node:crypto";
const [port, keyFile, certFile] = process.argv.slice(2);
const N_IMG = 120, N_JS = 20;
const page = `<!doctype html><html><head><title>loading</title><link rel=stylesheet href="/s.css"></head><body>
${Array.from({ length: N_IMG }, (_, i) => `<img src="/a/${i}.svg" width=8 height=8>`).join("")}
${Array.from({ length: N_JS }, (_, i) => `<script src="/js/${i}.js"></script>`).join("")}
<script>
(async () => {
  const parts = [];
  const js = (window.loaded || []).length; parts.push("js=" + js);
  const ev = await new Promise((res) => { let n = 0; const es = new EventSource("/events");
    es.onmessage = () => { if (++n === 5) { es.close(); res(n); } }; es.onerror = () => { es.close(); res(n); }; setTimeout(() => res(n), 8000); });
  parts.push("events=" + ev);
  const big = await fetch("/big?mb=20").then((r) => r.arrayBuffer()).then((b) => b.byteLength).catch(() => -1);
  parts.push("big=" + big);
  const up = await fetch("/echo", { method: "POST", body: new Uint8Array(1 << 20) }).then((r) => r.text()).catch(() => "x");
  parts.push("echo=" + up);
  const slow = await fetch("/slow").then((r) => r.text()).catch(() => "x");
  parts.push("slow=" + slow);
  const ws = await new Promise((res) => { const w = new WebSocket("wss://localhost:" + (Number(location.port) + 1) + "/ws");
    w.onopen = () => w.send("ping"); w.onmessage = (m) => { res(m.data); w.close(); }; w.onerror = () => res("error"); setTimeout(() => res("timeout"), 5000); });
  parts.push("ws=" + ws);
  document.title = "done " + parts.join(" ");
})();
</script></body></html>`;
const server = http2.createSecureServer({ key: readFileSync(keyFile), cert: readFileSync(certFile), allowHTTP1: true });
server.on("request", (req, res) => {
  const u = new URL(req.url, "https://x");
  const send = (code, type, body, extra = {}) => { res.writeHead(code, { "content-type": type, "cache-control": "no-store", ...extra }); res.end(body); };
  if (u.pathname === "/") return send(200, "text/html", page);
  if (u.pathname === "/s.css") return send(200, "text/css", "img{margin:1px}");
  if (u.pathname.startsWith("/a/")) return send(200, "image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8" fill="#${(u.pathname.length * 99999).toString(16).slice(0, 6)}"/></svg>`);
  if (u.pathname.startsWith("/js/")) {
    const code = `window.loaded=(window.loaded||[]);window.loaded.push(${JSON.stringify(u.pathname)});` + "/*pad*/".repeat(400);
    return send(200, "text/javascript", zlib.gzipSync(code), { "content-encoding": "gzip" });
  }
  if (u.pathname === "/events") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
    let i = 0; const t = setInterval(() => { res.write(`data: ${i}\n\n`); if (++i === 5) { clearInterval(t); res.end(); } }, 200);
    req.on("close", () => clearInterval(t)); return;
  }
  if (u.pathname === "/big") {
    const n = Number(u.searchParams.get("mb") || 1) << 20; res.writeHead(200, { "content-type": "application/octet-stream", "content-length": n, "cache-control": "no-store" });
    const chunk = Buffer.alloc(65536, 120); let sent = 0;
    const pump = () => { while (sent < n) { const k = Math.min(chunk.length, n - sent); sent += k; if (!res.write(chunk.subarray(0, k))) return res.once("drain", pump); } res.end(); };
    return pump();
  }
  if (u.pathname === "/echo") { let n = 0; req.on("data", (d) => (n += d.length)); req.on("end", () => send(200, "text/plain", String(n))); return; }
  if (u.pathname === "/slow") return setTimeout(() => send(200, "text/plain", "late"), 3000);
  send(404, "text/plain", "nope");
});
server.listen(Number(port), "127.0.0.1", () => console.log("site on", port));

// A WebSocket echo server over TLS on port + 1 (small text frames only).
const wss = https.createServer({ key: readFileSync(keyFile), cert: readFileSync(certFile) });
wss.on("upgrade", (req, sock) => {
  const accept = crypto.createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
  sock.on("data", (b) => {
    if ((b[0] & 0x0f) !== 1) return sock.end();
    const len = b[1] & 0x7f, mask = b.subarray(2, 6);
    const data = Buffer.from(b.subarray(6, 6 + len).map((x, i) => x ^ mask[i % 4]));
    sock.write(Buffer.concat([Buffer.from([0x81, data.length + 5]), Buffer.from("echo:"), data]));
  });
  sock.on("error", () => {});
});
wss.listen(Number(port) + 1, "127.0.0.1");
