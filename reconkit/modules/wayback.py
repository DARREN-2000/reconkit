import json

from ..core.scope import host_of, is_ip
from ..core.utils import good, info, make_result

NAME = "wayback"
DESCRIPTION = "Passive URL discovery via the Wayback Machine (CDX)"

INTERESTING = (
    ".json",
    ".xml",
    ".sql",
    ".bak",
    ".old",
    ".zip",
    ".tar",
    ".gz",
    ".env",
    ".config",
    ".yml",
    ".yaml",
    ".log",
    ".txt",
    "admin",
    "login",
    "api",
    "backup",
    "config",
    "upload",
    "token",
    "key",
)


def run(target, ctx):
    domain = host_of(target)
    if not domain or is_ip(domain):
        return make_result(
            NAME, "target is an IP or empty; Wayback lookup skipped", [], {}
        )
    url = (
        "http://web.archive.org/cdx/search/cdx?url="
        + domain
        + "/*&output=json&fl=original&collapse=urlkey&limit=1000"
    )
    info("Wayback CDX query for " + domain)
    r = ctx.http.external(url)
    if not r or r.status >= 400 or not r.body:
        return make_result(
            NAME,
            "no Wayback data (network disabled or lookup failed)",
            [],
            {"queried": url},
        )
    try:
        rows = json.loads(r.text)
    except Exception:
        return make_result(
            NAME, "Wayback response was not valid JSON", [], {"queried": url}
        )
    urls = []
    body = (
        rows[1:]
        if (rows and isinstance(rows[0], list) and rows[0] and rows[0][0] == "original")
        else rows
    )
    for row in body:
        if isinstance(row, list) and row:
            urls.append(str(row[0]))
        elif isinstance(row, str):
            urls.append(row)
    urls = sorted(set(urls))
    interesting = [u for u in urls if any(k in u.lower() for k in INTERESTING)]
    for u in interesting[:100]:
        good(u)
    summary = (
        str(len(urls)) + " archived URL(s), " + str(len(interesting)) + " interesting"
    )
    findings = [{"url": u} for u in interesting[:300]]
    return make_result(NAME, summary, findings, {"queried": url, "total": len(urls)})
