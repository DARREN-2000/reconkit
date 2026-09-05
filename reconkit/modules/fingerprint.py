from html.parser import HTMLParser

from ..core.utils import base_url, good, make_result

NAME = "fingerprint"
DESCRIPTION = "Technology fingerprinting from headers and body"

HEADER_TECH = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
}
BODY_SIGS = [
    ("WordPress", "wp-content"),
    ("WordPress", "wp-includes"),
    ("Drupal", "drupal.settings"),
    ("Joomla", "/media/jui/"),
    ("React", "data-reactroot"),
    ("Angular", "ng-version"),
    ("Vue.js", "__vue__"),
    ("jQuery", "jquery"),
    ("Bootstrap", "bootstrap"),
    ("Laravel", "laravel_session"),
]


class _Meta(HTMLParser):
    def __init__(self):
        super().__init__()
        self.generator = ""

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs}
            if a.get("name", "").lower() == "generator":
                self.generator = a.get("content", "")


def run(target, ctx):
    base = base_url(target)
    resp = ctx.http.get(base)
    if resp is None:
        return make_result(NAME, "no response from target", [], {})
    findings = []
    for key, label in HEADER_TECH.items():
        if key in resp.headers:
            findings.append(
                {"technology": label, "evidence": str(resp.headers.get(key))[:80]}
            )
    m = _Meta()
    try:
        m.feed(resp.text)
    except Exception:
        pass
    if m.generator:
        findings.append({"technology": "generator", "evidence": m.generator})
    low = resp.text.lower()
    for tech, sig in BODY_SIGS:
        if sig in low:
            findings.append(
                {"technology": tech, "evidence": "body contains '" + sig + "'"}
            )
    for f in findings:
        good(f["technology"] + ": " + f["evidence"])
    summary = str(len(findings)) + " technology signal(s)"
    return make_result(NAME, summary, findings, {"signals": len(findings)})
