#!/usr/bin/env bash
# Real-world traffic patterns through the proxy: streaming (SSE, chunked),
# 300 MB downloads, 70 s long polls, 100-continue, uploads, keep-alive and
# connection reuse, stale connections, 204/304/HEAD/302/close-delimited,
# gzip byte-exactness. Over plain HTTP, HTTPS with HTTP/2 and HTTPS with
# HTTP/1.1 to the proxy.
#
#   PROXYMIND=target/debug/proxymind bench/proxy/run.sh [case ...]
#
# Needs python3, curl and openssl. Takes about 5 minutes (long polls).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=${PROXYMIND:-$here/../../target/debug/proxymind}
work=$(mktemp -d)
trap 'kill $(cat "$work"/*.pid 2>/dev/null) 2>/dev/null || true; rm -rf "$work"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/k.pem" -out "$work/c.pem" -days 2 -subj "/CN=localhost" 2>/dev/null
cat "$work/k.pem" "$work/c.pem" > "$work/both.pem"
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
hp=$(port); sp=$(port); pp=$(port)
python3 "$here/target_server.py" "$hp" "$sp" "$work/both.pem" > "$work/server.log" 2>&1 & echo $! > "$work/server.pid"
"$bin" proxy -p "$work/p.pmproj" --home "$work/home" -l "127.0.0.1:$pp" > "$work/proxy.log" 2>&1 & echo $! > "$work/proxy.pid"
for _ in $(seq 50); do [ -f "$work/home/proxymind-ca.pem" ] && break; sleep 0.1; done
sleep 1
python3 "$here/matrix.py" "127.0.0.1:$pp" "$hp" "$sp" "$work/home/proxymind-ca.pem" "$@"
