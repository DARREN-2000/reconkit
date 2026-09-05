from ..core.utils import base_url, make_result, warn

NAME = "headers"
DESCRIPTION = "HTTP security header audit"

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "clickjacking protection",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "referrer policy",
    "permissions-policy": "permissions policy",
}
LEAKY = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
    "via",
]


def run(target, ctx):
    base = base_url(target)
    resp = ctx.http.get(base)
    if resp is None:
        return make_result(NAME, "no response from target", [], {})
    h = resp.headers
    findings = []
    missing = 0
    for key, label in SECURITY_HEADERS.items():
        if key not in h:
            missing += 1
            warn("missing " + key + " (" + label + ")")
            findings.append({"header": key, "status": "missing", "detail": label})
        else:
            findings.append(
                {"header": key, "status": "present", "detail": str(h.get(key))[:80]}
            )
    for key in LEAKY:
        if key in h:
            findings.append(
                {"header": key, "status": "info-leak", "detail": str(h.get(key))[:80]}
            )
    summary = str(missing) + " security header(s) missing"
    return make_result(NAME, summary, findings, {"missing": missing})
