from ..core.utils import base_url, good, make_result, warn

NAME = "cors"
DESCRIPTION = "CORS misconfiguration checks"

EVIL = "https://evil.example"


def run(target, ctx):
    base = base_url(target)
    findings = []
    r = ctx.http.get(base, headers={"Origin": EVIL}, allow_redirects=True)
    if not r:
        return make_result(NAME, "no HTTP response", [], {})
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao == EVIL:
        sev = "high" if acac else "medium"
        findings.append(
            {
                "issue": "origin reflection",
                "acao": acao,
                "credentials": acac,
                "severity": sev,
            }
        )
        warn("CORS reflects arbitrary Origin (credentials=" + str(acac) + ")")
    elif acao == "*":
        findings.append(
            {
                "issue": "wildcard ACAO",
                "acao": "*",
                "credentials": acac,
                "severity": "high" if acac else "low",
            }
        )
        warn("CORS allows any origin (*)")
    r2 = ctx.http.get(base, headers={"Origin": "null"}, allow_redirects=True)
    if r2 and r2.headers.get("access-control-allow-origin", "") == "null":
        cred2 = r2.headers.get("access-control-allow-credentials", "").lower() == "true"
        findings.append(
            {
                "issue": "null origin allowed",
                "acao": "null",
                "credentials": cred2,
                "severity": "medium",
            }
        )
        warn("CORS allows null origin")
    if not findings:
        good("no obvious CORS misconfiguration")
    summary = (
        (str(len(findings)) + " CORS issue(s)")
        if findings
        else "no CORS misconfiguration detected"
    )
    return make_result(NAME, summary, findings, {})
