from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from ..core.scope import host_of
from ..core.utils import base_url, good, make_result

NAME = "params"
DESCRIPTION = "Form and query-parameter extraction (attack surface mapping)"


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {
                "action": a.get("action", ""),
                "method": (a.get("method", "get") or "get").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if name:
                self._cur["inputs"].append(name)
        if tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def run(target, ctx):
    base = base_url(target)
    r = ctx.http.get(base, allow_redirects=True)
    if not r:
        return make_result(NAME, "no HTTP response", [], {})
    parser = _Parser()
    try:
        parser.feed(r.text)
    except Exception:
        pass
    findings = []
    for form in parser.forms:
        action = urljoin(base + "/", form["action"]) if form["action"] else base
        names = ", ".join(form["inputs"])
        findings.append(
            {
                "type": "form",
                "method": form["method"],
                "action": action,
                "params": names or "(none)",
            }
        )
        good("form " + form["method"] + " " + action + " [" + names + "]")
    seen = set()
    host = host_of(base)
    for href in parser.links:
        full = urljoin(base + "/", href)
        pu = urlparse(full)
        if pu.query and host_of(full) == host:
            for key in parse_qs(pu.query).keys():
                sig = pu.path + "?" + key
                if sig not in seen:
                    seen.add(sig)
                    findings.append(
                        {
                            "type": "query",
                            "method": "GET",
                            "action": pu.path,
                            "params": key,
                        }
                    )
    nforms = len([f for f in findings if f["type"] == "form"])
    nquery = len([f for f in findings if f["type"] == "query"])
    summary = str(nforms) + " form(s), " + str(nquery) + " query param(s)"
    return make_result(
        NAME, summary, findings, {"forms": nforms, "query_params": nquery}
    )
