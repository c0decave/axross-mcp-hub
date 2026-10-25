"""Local test target of the hub's smoke tests (tests/axross-smoke.json, target "web").

Deliberately vulnerable: /item builds its SQL by string concatenation (SQL injection on
purpose, for sqlmap). Run it only in a disposable container published on an address that
is not reachable from other machines (a host-only bridge), and stop it after the test.

    /              HTML index linking /item?id=1
    /item?id=N     the item's name from an in-memory SQLite table (injectable)
    /admin         200 "admin area"
    /robots.txt    Disallow: /admin
    anything else  404
"""
import sqlite3, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
db = sqlite3.connect(":memory:", check_same_thread=False)
# sqlmap's heavy time-based payloads (RANDOMBLOB(500000000)) must fail inside SQLite, not
# grow the process past the container's memory limit (it was OOM-killed at 256 MiB).
db.execute("PRAGMA hard_heap_limit=67108864")
db.executescript("CREATE TABLE items(id INTEGER, name TEXT); INSERT INTO items VALUES (1,'apple'),(2,'pear');"
                 "CREATE TABLE users(id INTEGER, login TEXT, secret TEXT); INSERT INTO users VALUES (1,'admin','s3cr3t');")
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if u.path == "/item":
            try:
                rows = db.execute("SELECT name FROM items WHERE id = " + q.get("id", ["1"])[0]).fetchall()
                body = "<html><body>" + "".join(f"<p>{r[0]}</p>" for r in rows) + "</body></html>"
                code = 200
            except Exception as e:
                body, code = f"<html><body>error</body></html>", 500
        elif u.path in ("/", "/index.html"):
            body, code = "<html><head><title>hub test target</title></head><body><a href='/item?id=1'>item</a></body></html>", 200
        elif u.path == "/admin":
            body, code = "<html><body>admin area</body></html>", 200
        elif u.path == "/robots.txt":
            body, code = "User-agent: *\nDisallow: /admin\n", 200
        else:
            body, code = "<html><body>not found</body></html>", 404
        data = body.encode()
        self.send_response(code); self.send_header("Content-Type", "text/html"); self.send_header("Server", "hubtest/1.0")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
