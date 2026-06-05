import hashlib
import hmac
import json
import os
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ.get("PURPLEWOLF_SECRET", "").encode()
RECORD_PATH = os.environ.get("RECORD_PATH", "/shared/requests.jsonl")
SKEW_S = 300
SEEN = OrderedDict()
SEEN_CAP = 10000


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return

        ts = self.headers.get("X-PurpleWolf-Timestamp", "")
        sig = self.headers.get("X-PurpleWolf-Signature", "")
        event_id = self.headers.get("X-PurpleWolf-Event-Id", "")
        if not (ts.isdigit() and sig.startswith("sha256=") and event_id):
            self.send_response(400)
            self.end_headers()
            return
        if abs(time.time() - int(ts)) > SKEW_S:
            self.send_response(401)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        mac = hmac.new(SECRET, f"{ts}.".encode() + body, hashlib.sha256)
        expected = "sha256=" + mac.hexdigest()
        if not hmac.compare_digest(expected, sig):
            self.send_response(401)
            self.end_headers()
            return

        if event_id not in SEEN:
            SEEN[event_id] = time.time()
            if len(SEEN) > SEEN_CAP:
                SEEN.popitem(last=False)
            record = {
                "event_id": event_id,
                "delivery_id": self.headers.get("X-PurpleWolf-Delivery-Id", ""),
                "attempt": self.headers.get("X-PurpleWolf-Attempt", ""),
                "body": json.loads(body.decode()),
            }
            line = json.dumps(record, separators=(",", ":"))
            with open(RECORD_PATH, "a") as f:
                f.write(line + "\n")
            print(line, flush=True)

        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
