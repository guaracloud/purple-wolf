"""Byte-faithful HTTP echo backend for the real-Traefik integration suite."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size_line = self.rfile.readline()
                size = int(size_line.split(b";", 1)[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                chunks.append(self.rfile.read(size))
                if self.rfile.read(2) != b"\r\n":
                    raise ValueError("malformed chunk terminator")
            return b"".join(chunks)

        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def respond(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.respond(b"ok")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self.respond(self.read_body())

    def log_message(self, _format: str, *_args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), EchoHandler).serve_forever()
