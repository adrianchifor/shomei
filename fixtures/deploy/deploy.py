import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock


ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/deploy.js": ("deploy.js", "text/javascript; charset=utf-8"),
}


class DeployAPI(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ASSETS:
            name, content_type = ASSETS[self.path]
            self.send_body(Path(__file__).with_name(name).read_bytes(), content_type)
            return
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
        self.send_body(json.dumps(value).encode(), "application/json")

    def send_body(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    with ThreadingHTTPServer(("127.0.0.1", 8080), DeployAPI) as server:
        server.lock = Lock()
        server.revision = 0
        server.serve_forever()
