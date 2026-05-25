"""Mock purple-wolf webhook subscriber for docker-compose integration.

Verifies the HMAC, dedupes on X-PurpleWolf-Event-Id, and records each
unique delivery as one JSON line on $RECORD_PATH (default
/shared/requests.jsonl). The test harness reads that file after
driving traffic through the WAF.
"""

import hashlib
import hmac
import json
import os
import time
from collections import OrderedDict
from flask import Flask, request, abort

SECRET = os.environ.get("PURPLEWOLF_SECRET", "").encode()
RECORD_PATH = os.environ.get("RECORD_PATH", "/shared/requests.jsonl")
SKEW_S = 300  # 5 minutes
SEEN = OrderedDict()
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
    mac = hmac.new(SECRET, f"{ts}.".encode() + body, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(401)
    if eid in SEEN:
        return ("", 200)
    SEEN[eid] = time.time()
    if len(SEEN) > SEEN_CAP:
        SEEN.popitem(last=False)

    record = {
        "event_id": eid,
        "delivery_id": request.headers.get("X-PurpleWolf-Delivery-Id", ""),
        "attempt": request.headers.get("X-PurpleWolf-Attempt", ""),
        "body": json.loads(body.decode()),
    }
    with open(RECORD_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")
    return ("", 200)


if __name__ == "__main__":
    # Bind on 0.0.0.0 so the test harness on the docker bridge can reach.
    app.run(host="0.0.0.0", port=8090)
