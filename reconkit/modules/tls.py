import socket
import ssl

from ..core.scope import host_of
from ..core.utils import good, info, make_result

NAME = "tls"
DESCRIPTION = "TLS/SSL certificate and protocol inspection"


def run(target, ctx):
    host = host_of(target)
    if not host:
        return make_result(NAME, "no host resolved from target", [], {})
    port = int(ctx.options.get("tls_port", 0) or 443)
    info("TLS handshake to " + host + ":" + str(port))
    context = ssl.create_default_context()
    if ctx.options.get("insecure", False):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection(
                (host, port), timeout=min(ctx.timeout, 5.0)
            ) as sock,
            context.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            proto = ssock.version()
            cipher = ssock.cipher()
            cert = ssock.getpeercert()
    except Exception as e:
        return make_result(
            NAME, "TLS connection failed (" + type(e).__name__ + ")", [], {}
        )
    findings = []
    if proto:
        findings.append({"field": "protocol", "value": proto})
    if cipher:
        findings.append({"field": "cipher", "value": str(cipher[0])})
        findings.append({"field": "tls_bits", "value": str(cipher[2])})
    if cert:
        subj = dict(x[0] for x in cert.get("subject", []) if x)
        issuer = dict(x[0] for x in cert.get("issuer", []) if x)
        if subj.get("commonName"):
            findings.append({"field": "subject_cn", "value": subj["commonName"]})
        if issuer.get("organizationName"):
            findings.append({"field": "issuer", "value": issuer["organizationName"]})
        if cert.get("notAfter"):
            findings.append({"field": "not_after", "value": cert["notAfter"]})
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        for s in sans[:25]:
            findings.append({"field": "san", "value": s})
    for f in findings:
        good(f["field"] + ": " + f["value"])
    summary = ("TLS " + proto + " negotiated") if proto else "TLS inspected"
    return make_result(NAME, summary, findings, {"protocol": proto or "", "port": port})
