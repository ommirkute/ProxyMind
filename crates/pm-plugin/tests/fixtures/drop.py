import sys, json, base64
def frames():
    for line in sys.stdin:
        if line.strip():
            yield json.loads(line)
def out(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()

for f in frames():
    out({"id": f["id"], "action": "drop"})
