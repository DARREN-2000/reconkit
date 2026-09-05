from ..core.http import HttpClient
from ..core.utils import base_url, good, make_result

NAME = "defaultcreds"
DESCRIPTION = "Default-credential checks on HTTP Basic auth (authorized only)"

DEFAULTS = [
    "admin:admin",
    "admin:password",
    "admin:",
    "administrator:administrator",
    "root:root",
    "root:toor",
    "user:user",
    "guest:guest",
    "test:test",
    "tomcat:tomcat",
    "manager:manager",
]
PROBE_PATHS = [
    "/",
    "/admin",
    "/administrator",
    "/manager/html",
    "/private",
    "/api",
    "/login",
]


def run(target, ctx):
    base = base_url(target)
    creds = list(DEFAULTS)
    for c in (ctx.options.get("creds", "") or "").split(","):
        c = c.strip()
        if c and ":" in c and c not in creds:
            creds.append(c)
    findings = []
    realms = 0
    for path in PROBE_PATHS:
        url = base + path
        resp = ctx.http.get(url, allow_redirects=False)
        if resp is None:
            continue
        if (
            resp.status != 401
            or "basic" not in resp.headers.get("www-authenticate", "").lower()
        ):
            continue
        realms += 1
        for cred in creds:
            user, _, pw = cred.partition(":")
            r = ctx.http.get(
                url,
                allow_redirects=False,
                headers={"Authorization": HttpClient.basic_auth(user, pw)},
            )
            if r is not None and r.status < 400:
                good("default creds work: " + cred + " @ " + path)
                findings.append({"url": url, "cred": cred, "status": r.status})
                break
    summary = (
        (str(len(findings)) + " default-credential hit(s)")
        if findings
        else ("no default creds (" + str(realms) + " basic-auth realm(s))")
    )
    return make_result(
        NAME, summary, findings, {"realms": realms, "hits": len(findings)}
    )
