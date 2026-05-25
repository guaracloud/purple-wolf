"""Reference purple-wolf-relay subscriber in Python (Flask).

Run:
    pip install flask
    PURPLEWOLF_SECRET=$(openssl rand -hex 32) python python.py

Verifies the HMAC, checks timestamp skew (replay protection), dedupes
on event_id, and responds 200 on success. Maps directly to the snippet
in docs/webhook-protocol.md.
"""

import hashlib
import hmac
import json
import os
import time
from collections import OrderedDict
from flask import Flask, request, abort

SECRET = os.environ["PURPLEWOLF_SECRET"].encode()
SKEW_S = 300
SEEN: "OrderedDict[str, float]" = OrderedDict()
SEEN_CAP = 10_000

app = Flask(__name__)


@app.post("/webhook")
def receive():
    ts = request.headers.get("X-PurpleWolf-Timestamp", "")
    sig = request.headers.get("X-PurpleWolf-Signature", "")
    eid = request.headers.get("X-PurpleWolf-Event-Id", "")
    if not (ts.isdigit() and sig.startswith("sha256=") and eid):
        abort(400)
    if abs(time.time() - int(ts)) > SKEW_S:
        abort(401)
    body = request.get_data()
    expected = "sha256=" + hmac.new(
        SECRET, f"{ts}.".encode() + body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(401)
    if eid in SEEN:
        return ("", 200)
    SEEN[eid] = time.time()
    if len(SEEN) > SEEN_CAP:
        SEEN.popitem(last=False)
    event = json.loads(body)
    print(json.dumps(event, indent=2))
    return ("", 200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
