import socket

from ..core.scope import host_of, is_ip
from ..core.utils import good, make_result

NAME = "dns"
DESCRIPTION = "DNS resolution (A/AAAA) and reverse PTR lookups"


def run(target, ctx):
    host = host_of(target)
    if not host:
        return make_result(NAME, "no host resolved from target", [], {})
    findings = []
    if is_ip(host):
        try:
            name, aliases, _ = socket.gethostbyaddr(host)
            findings.append({"type": "PTR", "value": name})
            for a in aliases:
                findings.append({"type": "PTR-alias", "value": a})
        except Exception:
            pass
    else:
        try:
            infos = socket.getaddrinfo(host, None)
            v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
            v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
            for ip in v4:
                findings.append({"type": "A", "value": ip})
            for ip in v6:
                findings.append({"type": "AAAA", "value": ip})
            for ip in v4:
                try:
                    findings.append(
                        {"type": "PTR", "value": socket.gethostbyaddr(ip)[0]}
                    )
                except Exception:
                    pass
        except Exception:
            pass
    for f in findings:
        good(f["type"] + "  " + f["value"])
    summary = str(len(findings)) + " DNS record(s)"
    return make_result(NAME, summary, findings, {"records": len(findings)})
