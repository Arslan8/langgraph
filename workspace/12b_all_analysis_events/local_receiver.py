"""A real temporary loopback receiver; no external destination is contacted."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, urlopen


@contextmanager
def local_receiver():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"received")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def send(body):
        request = Request(
            f"http://127.0.0.1:{server.server_port}/", data=body, method="POST"
        )
        with urlopen(request, timeout=5) as response:
            return response.read()

    try:
        yield send, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
