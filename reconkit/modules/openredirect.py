from urllib.parse import quote

from ..core.utils import base_url, make_result, warn

NAME = "openredirect"
DESCRIPTION = "Open-redirect probing on common redirect params and paths"

EVIL = "https://evil.example/"
PARAMS = [
    "url",
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "returnurl",
    "dest",
    "destination",
    "continue",
    "r",
    "u",
    "go",
    "target",
    "to",
]
PATHS = ["/redirect", "/go", "/out", "/away", "/link", "/exit", "/r"]


def _open_to_evil(resp):
    if resp is None or resp.status not in (301, 302, 303, 307, 308):
        return None
    loc = resp.headers.get("location", "")
    low = loc.lower()
    if low.startswith(
        ("https://evil.example", "http://evil.example", "//evil.example")
    ):
        return loc
    return None


def run(target, ctx):
    base = base_url(target)
    findings = []
    ev = quote(EVIL, safe="")
    for param in PARAMS:
        resp = ctx.http.get(base + "/?" + param + "=" + ev, allow_redirects=False)
        loc = _open_to_evil(resp)
        if loc:
            warn("open redirect via ?" + param)
            findings.append(
                {
                    "type": "param",
                    "vector": param,
                    "status": resp.status,
                    "location": loc,
                }
            )
    seen = set()
    for path in PATHS:
        for param in ("url", "next", "redirect", "u", "dest"):
            resp = ctx.http.get(
                base + path + "?" + param + "=" + ev, allow_redirects=False
            )
            loc = _open_to_evil(resp)
            if loc and path not in seen:
                seen.add(path)
                warn("open redirect via path " + path)
                findings.append(
                    {
                        "type": "path",
                        "vector": path,
                        "status": resp.status,
                        "location": loc,
                    }
                )
                break
    summary = (
        (str(len(findings)) + " open-redirect vector(s)")
        if findings
        else "no open redirect detected"
    )
    return make_result(NAME, summary, findings, {"vectors": len(findings)})
