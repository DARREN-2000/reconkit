import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from ..core.scope import host_of
from ..core.utils import base_url, info, make_result

NAME = "spider"
DESCRIPTION = "Same-origin crawler mapping pages, links, and emails"

_EMAIL = re.compile("[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+[.][A-Za-z0-9.-]+")


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link") and a.get("href"):
            self.hrefs.append(a["href"])
        elif tag in ("script", "img", "iframe") and a.get("src"):
            self.hrefs.append(a["src"])


def run(target, ctx):
    base = base_url(target)
    host = host_of(target)
    max_pages = int(ctx.options.get("max_pages", 25) or 25)
    to_visit = [base]
    visited = set()
    pages = []
    links = set()
    emails = set()
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        resp = ctx.http.get(url)
        if resp is None or not resp.text:
            continue
        pages.append(url)
        for em in _EMAIL.findall(resp.text):
            emails.add(em)
        parser = _LinkParser()
        try:
            parser.feed(resp.text)
        except Exception:
            pass
        for href in parser.hrefs:
            if href.lower().startswith("mailto:"):
                emails.add(href.split(":", 1)[1].split("?")[0])
                continue
            full = urljoin(url, href).split("#")[0]
            pu = urlparse(full)
            if pu.scheme not in ("http", "https"):
                continue
            if pu.netloc.split(":")[0].lower() != host:
                continue
            links.add(full)
            if (
                full not in visited
                and full not in to_visit
                and len(to_visit) < max_pages * 4
            ):
                to_visit.append(full)
    findings = [{"type": "page", "value": u} for u in pages]
    findings += [{"type": "email", "value": e} for e in sorted(emails)]
    info(
        str(len(pages))
        + " page(s), "
        + str(len(links))
        + " link(s), "
        + str(len(emails))
        + " email(s)"
    )
    summary = (
        str(len(pages))
        + " page(s) crawled, "
        + str(len(links))
        + " link(s), "
        + str(len(emails))
        + " email(s)"
    )
    return make_result(
        NAME,
        summary,
        findings,
        {"pages": len(pages), "links": len(links), "emails": len(emails)},
    )
