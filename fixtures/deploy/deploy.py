import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock


class DeployAPI(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/status":
            self.send_error(404)
            return
        with self.server.lock:
            revision = self.server.revision
        self.reply({"revision": revision})

    def do_POST(self):
        if self.path != "/api/deploy":
            self.send_error(404)
            return
        with self.server.lock:
            self.server.revision += 1
            revision = self.server.revision
        self.reply({"revision": revision, "message": f"Demo service deployed. Revision {revision}."})

    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    with ThreadingHTTPServer(("127.0.0.1", 8080), DeployAPI) as server:
        server.lock = Lock()
        server.revision = 0
        server.serve_forever()
