from urllib.parse import urljoin
from xml.etree import ElementTree

from ..core.utils import base_url, good, info, make_result

NAME = "robots"
DESCRIPTION = "robots.txt and sitemap.xml path harvesting"


def _parse_robots(text):
    paths = []
    sitemaps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("disallow:") or low.startswith("allow:"):
            val = line.split(":", 1)[1].strip()
            if val:
                paths.append(val)
        elif low.startswith("sitemap:"):
            val = line.split(":", 1)[1].strip()
            if val:
                sitemaps.append(val)
    return paths, sitemaps


def _parse_sitemap(text):
    locs = []
    try:
        root = ElementTree.fromstring(text)
    except Exception:
        return locs
    for el in root.iter():
        if el.tag.endswith("loc") and el.text:
            locs.append(el.text.strip())
    return locs


def run(target, ctx):
    base = base_url(target)
    findings = []
    r = ctx.http.get(base + "/robots.txt")
    sitemaps = []
    if r and r.status == 200 and r.text.strip():
        paths, sitemaps = _parse_robots(r.text)
        info(
            "robots.txt: "
            + str(len(paths))
            + " path rule(s), "
            + str(len(sitemaps))
            + " sitemap(s)"
        )
        for p in paths:
            findings.append({"source": "robots.txt", "type": "path", "value": p})
            good("robots path: " + p)
    else:
        info("no robots.txt")
    if not sitemaps:
        sitemaps = [base + "/sitemap.xml"]
    seen = set()
    for sm in sitemaps[:5]:
        target_url = sm if sm.startswith("http") else urljoin(base + "/", sm)
        sr = ctx.http.get(target_url)
        if sr and sr.status == 200 and sr.text.strip():
            locs = _parse_sitemap(sr.text)
            new = 0
            for loc in locs:
                if loc not in seen:
                    seen.add(loc)
                    findings.append({"source": "sitemap", "type": "url", "value": loc})
                    new += 1
            if new:
                good("sitemap " + target_url + ": " + str(new) + " URL(s)")
    summary = str(len(findings)) + " path(s)/URL(s) from robots + sitemap"
    return make_result(NAME, summary, findings, {"sitemaps": sitemaps})
