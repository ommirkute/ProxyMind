import sys, json, base64
def frames():
    for line in sys.stdin:
        if line.strip():
            yield json.loads(line)
def out(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()

for f in frames():
    raw = base64.b64decode(f["raw"])
    head, sep, body = raw.partition(b"\r\n\r\n")
    raw = head + b"\r\nX-Hooked: yes" + sep + body
    out({"id": f["id"], "action": "replace", "raw": base64.b64encode(raw).decode(), "note": "added X-Hooked"})
