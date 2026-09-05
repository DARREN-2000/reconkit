import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from ..core.scope import host_of
from ..core.utils import base_url, make_result, mask, warn

NAME = "secrets"
DESCRIPTION = "Secret and API-key scanning in HTML/JS bodies"

_Q = "[" + chr(34) + chr(39) + "]"
PATTERNS = [
    ("AWS access key", re.compile("AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile("AIza[0-9A-Za-z_-]{35}")),
    ("Slack token", re.compile("xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Private key", re.compile("-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----")),
    (
        "Generic secret",
        re.compile(
            "(?i)(?:api[_-]?key|apikey|secret|token|access[_-]?key|password|passwd)[ ]{0,3}[:=][ ]{0,3}"
            + _Q
            + "?([0-9A-Za-z_-]{8,64})"
        ),
    ),
]


class _ScriptSrc(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            a = dict(attrs)
            if a.get("src"):
                self.srcs.append(a["src"])


def _scan(text, source, out, seen):
    for label, rx in PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            sig = (label, val)
            if sig in seen:
                continue
            seen.add(sig)
            out.append({"type": label, "match": mask(val, 6), "source": source})


def run(target, ctx):
    base = base_url(target)
    host = host_of(target)
    resp = ctx.http.get(base)
    if resp is None:
        return make_result(NAME, "no response from target", [], {})
    findings = []
    seen = set()
    _scan(resp.text, base, findings, seen)
    parser = _ScriptSrc()
    try:
        parser.feed(resp.text)
    except Exception:
        pass
    scanned = 1
    for src in parser.srcs[:15]:
        url = urljoin(base, src)
        if host_of(url) != host:
            continue
        r = ctx.http.get(url)
        if r is not None and r.text:
            scanned += 1
            _scan(r.text, url, findings, seen)
    for f in findings:
        warn(f["type"] + " in " + f["source"])
    summary = (
        str(len(findings))
        + " potential secret(s) across "
        + str(scanned)
        + " document(s)"
    )
    return make_result(
        NAME, summary, findings, {"secrets": len(findings), "scanned": scanned}
    )
