#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib


class Handler(BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self._read_body()
        data = ("method=POST\n"
                "path=%s\n"
                "size=%d\n"
                "sha1=%s\n" % (self.path, len(body),
                               hashlib.sha1(body).hexdigest()))
        payload = data.encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length is None:
            return b""

        return self.rfile.read(int(length))


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18081), Handler).serve_forever()
