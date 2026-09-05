import base64
import ssl
import urllib.error
import urllib.request

from .scope import host_of


class Resp:
    def __init__(self, url, status, headers, body, set_cookies=None):
        self.url = url
        self.status = status
        self.headers = headers
        self.body = body
        self.set_cookies = set_cookies or []

    @property
    def text(self):
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, scope_check=None):
        self.scope_check = scope_check
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.scope_check and not self.scope_check(newurl):
            return None # Refuse redirect
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _ssl_context(insecure=False):
    c = ssl.create_default_context()
    if insecure:
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c


def _cookies_from(headers_obj):
    try:
        return list(headers_obj.get_all("Set-Cookie") or [])
    except Exception:
        return []


class HttpClient:
    def __init__(self, ctx):
        self.ctx = ctx
        opts = getattr(ctx, "options", {}) or {}
        self.insecure = opts.get("insecure", False)
        self.ua = opts.get("user_agent") or "reconkit/2.1 (authorized security testing)"
        self.extra = {}
        cookie = opts.get("cookie")
        if cookie:
            self.extra["Cookie"] = cookie
        auth = opts.get("auth_header")
        if auth and ":" in auth:
            k, v = auth.split(":", 1)
            self.extra[k.strip()] = v.strip()

    def _open(self, url, method, headers, data, allow_redirects, max_bytes, scoped):
        if scoped and not self.ctx.scope.allows(host_of(url)):
            return None
        self.ctx.rate.wait()
        
        handlers = [urllib.request.HTTPSHandler(context=_ssl_context(self.insecure))]
        
        if not allow_redirects:
            handlers.append(_NoRedirect())
        else:
            if scoped:
                handlers.append(_ScopedRedirect(lambda u: self.ctx.scope.allows(host_of(u))))
                
        opener = urllib.request.build_opener(*handlers)

        h = {"User-Agent": self.ua}
        h.update(self.extra)
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, method=method, headers=h, data=data)
        try:
            resp = opener.open(req, timeout=self.ctx.timeout)
            rheaders = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(max_bytes) if method != "HEAD" else b""
            return Resp(
                resp.geturl(),
                resp.getcode(),
                rheaders,
                body,
                _cookies_from(resp.headers),
            )
        except urllib.error.HTTPError as e:
            eh = e.headers
            rheaders = {k.lower(): v for k, v in (eh.items() if eh else [])}
            body = b""
            try:
                body = e.read(max_bytes)
            except Exception:
                pass
            return Resp(url, e.code, rheaders, body, _cookies_from(eh) if eh else [])
        except Exception:
            return None

    def request(
        self,
        url,
        method="GET",
        allow_redirects=True,
        max_bytes=300000,
        headers=None,
        data=None,
    ):
        return self._open(url, method, headers, data, allow_redirects, max_bytes, True)

    def get(self, url, **kw):
        return self.request(url, "GET", **kw)

    def head(self, url, **kw):
        return self.request(url, "HEAD", **kw)

    def post(self, url, data=None, **kw):
        return self.request(url, "POST", data=data, **kw)

    def external(self, url, headers=None, max_bytes=1000000):
        # For third-party OSINT services (crt.sh, Wayback, RDAP) - NOT the target.
        return self._open(url, "GET", headers, None, True, max_bytes, False)

    @staticmethod
    def basic_auth(user, password):
        raw = (user + ":" + password).encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")
