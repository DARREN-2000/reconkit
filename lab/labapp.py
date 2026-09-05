"""Acme Lab - a deliberately vulnerable local target for reconkit practice.

Run:   python3 labapp.py            # HTTP on 127.0.0.1:8080 + UDP echo on 8053
Scan:  python3 -m reconkit run http://127.0.0.1:8080 --authorized -g all --md notes.md

FOR LOCAL LAB USE ONLY. Do not expose this to a network.
"""

import base64
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

INDEX = """<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<meta name='generator' content='WordPress 6.2'>
<title>Acme Lab Portal</title>
<link rel='stylesheet' href='/wp-content/themes/acme/style.css'>
<script src='/static/app.js'></script>
</head>
<body>
<h1>Welcome to the Acme customer portal</h1>
<p>Search our catalog, manage your account, and contact support.</p>
<form action='/search' method='get'>
<input name='q' placeholder='Search products'>
<input type='hidden' name='csrf' value='tok123'>
<button type='submit'>Search</button>
</form>
<form action='/login' method='post'>
<input name='username' placeholder='Username'>
<input name='password' type='password' placeholder='Password'>
<button type='submit'>Sign in</button>
</form>
<ul>
<li><a href='/item?id=1'>Featured item</a></li>
<li><a href='/item?ref=promo'>Promoted item</a></li>
<li><a href='/search?q=popular'>Popular searches</a></li>
<li><a href='/go?url=https://partner.example.com'>Partner site</a></li>
<li><a href='/about'>About us</a></li>
</ul>
<p>Questions? Email <a href='mailto:admin@lab.local'>admin@lab.local</a> for support.</p>
<footer>Acme Corporation customer portal support catalog account orders invoices</footer>
</body>
</html>
"""

APPJS = """// Acme portal front-end config
var CONFIG = {
  region: 'us-east-1',
  s3_key: 'AKIAIOSFODNN7EXAMPLE',
  maps_key: 'AIzaSyD1234567890abcdefghijklmnopqrstuv',
  api_key: 'sk_live_0123456789abcdefghij',
  endpoint: '/api/v1'
};
console.log('portal loaded');
"""

ROBOTS = """User-agent: *
Disallow: /admin
Disallow: /private/
Disallow: /backup
Sitemap: http://lab.test/sitemap.xml
"""

SITEMAP = """<?xml version='1.0' encoding='UTF-8'?>
<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>
<url><loc>http://lab.test/</loc></url>
<url><loc>http://lab.test/about</loc></url>
<url><loc>http://lab.test/contact</loc></url>
</urlset>
"""

ADMIN_AUTH = "Basic " + base64.b64encode(b"admin:admin").decode()


class LabHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"
    sys_version = "(Ubuntu)"

    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="text/html", extra=None, cookies=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        for c in cookies or []:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path or "/"
        low = (u.query or "").lower()
        origin = self.headers.get("Origin")
        if path == "/robots.txt":
            return self._send(200, ROBOTS, "text/plain")
        if path == "/sitemap.xml":
            return self._send(200, SITEMAP, "application/xml")
        if path == "/static/app.js":
            return self._send(200, APPJS, "application/javascript")
        if path == "/admin":
            if self.headers.get("Authorization") == ADMIN_AUTH:
                return self._send(200, "<html>admin dashboard</html>")
            return self._send(
                401,
                "401 Unauthorized",
                extra={"WWW-Authenticate": 'Basic realm="admin"'},
            )
        if path in ("/go", "/redirect"):
            qs = parse_qs(u.query)
            dest = (
                qs.get("url")
                or qs.get("next")
                or qs.get("redirect")
                or qs.get("u")
                or qs.get("dest")
                or [""]
            )[0]
            if dest:
                return self._send(302, "", extra={"Location": dest})
            return self._send(200, "redirect service")
        if path == "/search":
            qs = parse_qs(u.query, keep_blank_values=True)
            q = (qs.get("q") or [""])[0]
            if "'" in q:
                return self._send(
                    500,
                    "<html>Database error: You have an error in your SQL syntax near '"
                    + q
                    + "'</html>",
                )
            return self._send(200, "<html><body>Results for: " + q + "</body></html>")
        if path == "/":
            if ("<script" in low) or ("or '1'='1" in low) or ("etc/passwd" in low):
                return self._send(
                    403,
                    "<html>Access Denied. This error was generated by Mod_Security.</html>",
                )
            extra = {}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            cookies = [
                "sessionid=abc123def456; Path=/",
                "secure_ok=1; Path=/; Secure; HttpOnly; SameSite=Strict",
            ]
            return self._send(200, INDEX, extra=extra, cookies=cookies)
        return self._send(404, "<html>404 Not Found</html>")


def _udp_echo(host="127.0.0.1", port=8053):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((host, port))
    except OSError:
        return
    while True:
        try:
            data, addr = s.recvfrom(2048)
            s.sendto(b"ACK:" + data[:32], addr)
        except OSError:
            break


def main(http_port=8080, udp_port=8053):
    threading.Thread(target=_udp_echo, kwargs={"port": udp_port}, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", http_port), LabHandler)
    print(
        "Acme Lab on http://127.0.0.1:"
        + str(http_port)
        + " (UDP echo :"
        + str(udp_port)
        + ") - Ctrl+C to stop"
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
