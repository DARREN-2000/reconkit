from ..core.utils import base_url, make_result, warn

NAME = "takeover"
DESCRIPTION = "Dangling-service subdomain takeover fingerprints"

FINGERPRINTS = [
    ("AWS S3", "the specified bucket does not exist"),
    ("AWS S3", "nosuchbucket"),
    ("GitHub Pages", "there isn't a github pages site here"),
    ("Heroku", "no such app"),
    ("Heroku", "herokucdn.com/error-pages/no-such-app.html"),
    ("Shopify", "sorry, this shop is currently unavailable"),
    ("Fastly", "fastly error: unknown domain"),
    ("Bitbucket", "repository not found"),
    ("Ghost", "the thing you were looking for is no longer here"),
    ("Surge.sh", "project not found"),
    ("Pantheon", "the gods are wise"),
    ("Tumblr", "there's nothing here"),
    ("Cargo", "the requested resource could not be found"),
    ("Netlify", "not found - request id"),
    ("Zendesk", "help center closed"),
]


def run(target, ctx):
    base = base_url(target)
    resp = ctx.http.get(base)
    if resp is None:
        return make_result(NAME, "no response from target", [], {})
    body = resp.text.lower()
    findings = []
    for service, sig in FINGERPRINTS:
        if sig in body:
            warn("possible " + service + " takeover signature")
            findings.append(
                {"service": service, "signature": sig, "status": resp.status}
            )
    summary = (
        (str(len(findings)) + " takeover signature(s)")
        if findings
        else "no takeover fingerprints matched"
    )
    return make_result(NAME, summary, findings, {"matched": len(findings)})
