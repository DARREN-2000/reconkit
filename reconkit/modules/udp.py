import socket

from ..core.scope import host_of
from ..core.utils import good, info, make_result

NAME = "udp"
DESCRIPTION = "UDP service discovery on common UDP ports"

COMMON_UDP = {
    53: "dns",
    67: "dhcp",
    69: "tftp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmp-trap",
    500: "ike",
    514: "syslog",
    520: "rip",
    1434: "ms-sql-m",
    1900: "ssdp",
    5353: "mdns",
}

_DNS_PROBE = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x07version\x04bind\x00\x00\x10\x00\x03"
)
_PROBES = {53: _DNS_PROBE}


def parse_ports(spec):
    ports = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                ports.extend(range(int(a), int(b) + 1))
        elif part.isdigit():
            ports.append(int(part))
    return [p for p in ports if 0 < p < 65536]


def _probe(host, port, timeout):
    payload = _PROBES.get(port, b"\x00")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(2048)
        return (port, "open", len(data))
    except TimeoutError:
        return (port, "open|filtered", 0)
    except OSError:
        return None
    finally:
        s.close()


def run(target, ctx):
    host = host_of(target)
    if not host:
        return make_result(NAME, "no host resolved from target", [], {})
    spec = ctx.options.get("udp_ports", "")
    ports = parse_ports(spec) if spec else sorted(COMMON_UDP)
    info("UDP probing " + str(len(ports)) + " port(s) on " + host)
    findings = []
    for p in ports:
        r = _probe(host, p, min(ctx.timeout, 3.0))
        if r is None:
            continue
        port, state, nbytes = r
        svc = COMMON_UDP.get(port, "unknown")
        if state == "open":
            good(
                "udp/"
                + str(port)
                + " ("
                + svc
                + ") responded ("
                + str(nbytes)
                + " bytes)"
            )
            findings.append(
                {"port": port, "service": svc, "state": state, "resp_bytes": nbytes}
            )
    summary = (
        str(len(findings)) + " UDP port(s) responded of " + str(len(ports)) + " probed"
    )
    return make_result(
        NAME, summary, findings, {"responded": len(findings), "probed": len(ports)}
    )
