#!/usr/bin/env bash
# Real-browser soak: Chromium (Playwright) loads a modern HTTPS site over
# HTTP/2 (120 images, 20 gzip scripts, server-sent events, a 20 MB fetch, a
# 1 MB upload, a slow request, a wss:// echo), four tabs at a time, directly
# and through ProxyMind, and compares. Optionally also a Juice Shop URL.
#
#   PROXYMIND=target/debug/proxymind bench/proxy/soak.sh [rounds] [juice-url]
#
# Needs node with playwright, and openssl.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=${PROXYMIND:-$here/../../target/debug/proxymind}
rounds=${1:-5}; juice=${2:-}
work=$(mktemp -d)
trap 'kill $(cat "$work"/*.pid 2>/dev/null) 2>/dev/null || true; rm -rf "$work"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/k.pem" -out "$work/c.pem" -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" 2>/dev/null
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
sp=$(port); pp=$(port)
# The site uses $sp and $sp+1 (wss).
node "$here/soak_site.mjs" "$sp" "$work/k.pem" "$work/c.pem" > "$work/site.log" 2>&1 & echo $! > "$work/site.pid"
"$bin" proxy -p "$work/p.pmproj" --home "$work/home" -l "127.0.0.1:$pp" > "$work/proxy.log" 2>&1 & echo $! > "$work/proxy.pid"
sleep 2
run() { env -u NO_PROXY -u no_proxy -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy node "$here/soak.mjs" "$@"; }
echo "== direct"; run "https://localhost:$sp/" "$rounds" "" $juice
echo "== through ProxyMind"; run "https://localhost:$sp/" "$rounds" "127.0.0.1:$pp" $juice
python3 - "$work/p.pmproj" <<'PY'
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
n = c.execute("select count(*) from exchanges").fetchone()[0]
e = c.execute("select count(*) from exchanges where error is not null").fetchone()[0]
print(f"history: {n} exchanges, {e} with errors")
for r in c.execute("select path, error from exchanges where error is not null limit 5"): print("  ", r)
PY
