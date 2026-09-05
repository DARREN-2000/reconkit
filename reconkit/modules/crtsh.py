import json

from ..core.scope import host_of, is_ip
from ..core.utils import good, info, make_result

NAME = "crtsh"
DESCRIPTION = "Passive subdomain discovery via crt.sh certificate transparency"


def run(target, ctx):
    domain = host_of(target)
    if not domain or is_ip(domain):
        return make_result(
            NAME, "target is an IP or empty; crt.sh lookup skipped", [], {}
        )
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    info("crt.sh query for " + domain)
    r = ctx.http.external(url)
    if not r or r.status >= 400 or not r.body:
        return make_result(
            NAME,
            "no crt.sh data (network disabled or lookup failed)",
            [],
            {"queried": url},
        )
    text = r.text.strip()
    try:
        rows = json.loads(text)
    except Exception:
        try:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        except Exception:
            return make_result(
                NAME, "crt.sh response was not valid JSON", [], {"queried": url}
            )
    names = set()
    for row in rows:
        nv = str(row.get("name_value", ""))
        for n in nv.replace("*.", "").splitlines():
            n = n.strip().lower().rstrip(".")
            if n and n.endswith(domain):
                names.add(n)
    found = sorted(names)
    for n in found[:200]:
        good(n)
    summary = str(len(found)) + " unique name(s) from certificate transparency"
    return make_result(
        NAME,
        summary,
        [{"subdomain": n} for n in found],
        {"queried": url, "count": len(found)},
    )
