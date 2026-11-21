import sys, json, base64
def frames():
    for line in sys.stdin:
        if line.strip():
            yield json.loads(line)
def out(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()

import time
for f in frames():
    time.sleep(1.5)
    out({"id": f["id"], "action": "pass"})
