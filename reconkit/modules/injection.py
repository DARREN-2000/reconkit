from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urljoin, urlparse

from ..core.scope import host_of
from ..core.utils import base_url, make_result, warn

NAME = "injection"
DESCRIPTION = "Safe reflected-XSS and SQL-error signal checks (assessment only)"

CANARY = "rk9x3q" + chr(60) + "svg" + chr(62)
SQL_PROBE = chr(39)
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "pg::syntaxerror",
    "psycopg2",
    "ora-01756",
    "odbc sql server driver",
    "sqlstate",
]


class _Surface(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        elif tag == "form":
            self._cur = {"action": a.get("action") or "", "params": []}
        elif (
            tag in ("input", "select", "textarea")
            and self._cur is not None
            and a.get("name")
        ):
            self._cur["params"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _targets(base, host, text):
    p = _Surface()
    try:
        p.feed(text)
    except Exception:
        pass
    out, seen = [], set()

    def add(path, key):
        if not key:
            return
        sig = (path or "/", key)
        if sig not in seen:
            seen.add(sig)
            out.append((path or "/", key))

    for href in p.hrefs:
        u = urlparse(urljoin(base, href))
        if u.netloc and u.netloc.split(":")[0].lower() != host:
            continue
        for key, _ in parse_qsl(u.query):
            add(u.path, key)
    for f in p.forms:
        ap = urlparse(urljoin(base, f["action"]))
        for name in f["params"]:
            add(ap.path, name)
    return out


def run(target, ctx):
    base = base_url(target)
    host = host_of(target)
    resp = ctx.http.get(base)
    text = resp.text if resp is not None else ""
    targets = _targets(base, host, text)
    if not targets:
        targets = [("/", k) for k in ("q", "id", "search", "s", "query", "page")]
    findings, tested = [], 0
    for path, param in targets:
        tested += 1
        endpoint = base + (path if path.startswith("/") else "/" + path)
        r1 = ctx.http.get(endpoint + "?" + param + "=" + quote(CANARY, safe=""))
        if r1 is not None and CANARY in r1.text:
            warn("reflected input: " + param + " @ " + path)
            findings.append(
                {"param": param, "type": "reflected-input", "endpoint": path}
            )
        r2 = ctx.http.get(
            endpoint + "?" + param + "=" + quote("1" + SQL_PROBE, safe="")
        )
        if r2 is not None and any(sig in r2.text.lower() for sig in SQL_ERRORS):
            warn("sql error signal: " + param + " @ " + path)
            findings.append({"param": param, "type": "sql-error", "endpoint": path})
    summary = (
        str(len(findings))
        + " injection signal(s) across "
        + str(tested)
        + " parameter(s)"
    )
    return make_result(
        NAME, summary, findings, {"signals": len(findings), "tested": tested}
    )
