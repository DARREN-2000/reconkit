import socket

from ..core.scope import host_of
from ..core.utils import good, info, make_result, thread_map

NAME = "ports"
DESCRIPTION = "TCP connect port scan with banner grabbing"

TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    8888,
    9200,
    27017,
]
SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1723: "pptp",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


def _parse_ports(spec):
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                out.extend(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.append(int(part))
    return [p for p in out if 0 < p < 65536]


def run(target, ctx):
    host = host_of(target)
    if not host:
        return make_result(NAME, "no host resolved from target", [], {})
    spec = ctx.options.get("ports", "")
    ports = _parse_ports(spec) if spec else list(TOP_PORTS)
    info("TCP scanning " + str(len(ports)) + " port(s) on " + host)

    def scan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(min(ctx.timeout, 3.0))
        try:
            if s.connect_ex((host, port)) != 0:
                return None
            banner = ""
            try:
                s.settimeout(1.0)
                banner = s.recv(120).decode("utf-8", "replace").strip()
            except Exception:
                banner = ""
            return {
                "port": port,
                "state": "open",
                "service": SERVICES.get(port, "unknown"),
                "banner": banner,
            }
        except Exception:
            return None
        finally:
            s.close()

    found = thread_map(scan, ports, min(ctx.workers, 200))
    found.sort(key=lambda f: f["port"])
    for f in found:
        good("tcp/" + str(f["port"]) + " open (" + f["service"] + ")")
    summary = str(len(found)) + " open TCP port(s) of " + str(len(ports)) + " scanned"
    return make_result(
        NAME, summary, found, {"open": len(found), "scanned": len(ports)}
    )
