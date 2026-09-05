import json

from ..core.scope import host_of, is_ip
from ..core.utils import good, info, make_result

NAME = "whois"
DESCRIPTION = "WHOIS/RDAP registration lookup (passive)"


def _events(obj):
    out = {}
    for ev in obj.get("events", []) or []:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action and date:
            out[action] = date
    return out


def _registrar(obj):
    for ent in obj.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        if "registrar" in roles:
            varr = ent.get("vcardArray")
            if isinstance(varr, list) and len(varr) > 1:
                for item in varr[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return item[3]
            return ent.get("handle", "")
    return ""


def run(target, ctx):
    host = host_of(target)
    if not host:
        return make_result(NAME, "no host in target", [], {})
    url = (
        ("https://rdap.org/ip/" + host)
        if is_ip(host)
        else ("https://rdap.org/domain/" + host)
    )
    info("RDAP lookup: " + url)
    r = ctx.http.external(url)
    if not r or r.status >= 400 or not r.body:
        return make_result(
            NAME,
            "no RDAP data (network disabled or lookup failed)",
            [],
            {"queried": url},
        )
    try:
        obj = json.loads(r.text)
    except Exception:
        return make_result(
            NAME, "RDAP response was not valid JSON", [], {"queried": url}
        )
    findings = []
    registrar = _registrar(obj)
    if registrar:
        findings.append({"field": "registrar", "value": registrar})
    for action, date in _events(obj).items():
        findings.append({"field": action, "value": date})
    nameservers = [
        ns.get("ldhName", "")
        for ns in obj.get("nameservers", []) or []
        if ns.get("ldhName")
    ]
    for ns in nameservers:
        findings.append({"field": "nameserver", "value": ns})
    statuses = obj.get("status", []) or []
    if statuses:
        findings.append({"field": "status", "value": ", ".join(statuses)})
    for f in findings:
        good(f["field"] + ": " + f["value"])
    summary = str(len(findings)) + " registration detail(s) for " + host
    return make_result(
        NAME, summary, findings, {"queried": url, "nameservers": nameservers}
    )
