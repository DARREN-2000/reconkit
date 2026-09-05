from ..core.utils import base_url, good, make_result, warn

NAME = "cookies"
DESCRIPTION = "Cookie security-flag audit (Secure, HttpOnly, SameSite)"


def _analyze(raw):
    parts = [p.strip() for p in raw.split(";")]
    first = parts[0] if parts else ""
    name = first.split("=", 1)[0] if "=" in first else first
    lowered = [p.lower() for p in parts]
    secure = "secure" in lowered
    httponly = "httponly" in lowered
    samesite = ""
    for p in parts:
        if p.lower().startswith("samesite"):
            samesite = p.split("=", 1)[1].strip() if "=" in p else "present"
    issues = []
    if not secure:
        issues.append("no Secure")
    if not httponly:
        issues.append("no HttpOnly")
    if not samesite:
        issues.append("no SameSite")
    return {
        "cookie": name or "(unnamed)",
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite or "(unset)",
        "issues": ", ".join(issues) or "ok",
    }


def run(target, ctx):
    r = ctx.http.get(base_url(target), allow_redirects=True)
    if not r:
        return make_result(NAME, "no HTTP response", [], {})
    cookies = list(r.set_cookies or [])
    if not cookies and "set-cookie" in r.headers:
        cookies = [r.headers["set-cookie"]]
    findings = []
    for raw in cookies:
        row = _analyze(raw)
        findings.append(row)
        (good if row["issues"] == "ok" else warn)(
            "cookie " + row["cookie"] + ": " + row["issues"]
        )
    flagged = [f for f in findings if f["issues"] != "ok"]
    summary = (
        str(len(findings)) + " cookie(s), " + str(len(flagged)) + " with weak flags"
    )
    return make_result(NAME, summary, findings, {"weak": len(flagged)})
