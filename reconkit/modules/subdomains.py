import socket

from ..core.scope import host_of, is_ip
from ..core.utils import good, make_result, thread_map

NAME = "subdomains"
DESCRIPTION = "DNS subdomain enumeration by resolution"

COMMON = [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "api",
    "dev",
    "staging",
    "app",
    "portal",
    "admin",
    "test",
    "m",
    "shop",
    "support",
    "status",
    "cdn",
    "docs",
    "git",
]


def run(target, ctx):
    domain = host_of(target)
    if not domain or is_ip(domain):
        return make_result(
            NAME, "target is an IP or empty; subdomain enumeration skipped", [], {}
        )
    names = [w + "." + domain for w in COMMON]

    def resolve(name):
        try:
            ips = sorted({i[4][0] for i in socket.getaddrinfo(name, None)})
            return {"subdomain": name, "ips": ", ".join(ips)}
        except Exception:
            return None

    found = thread_map(resolve, names, min(ctx.workers, 40))
    found.sort(key=lambda f: f["subdomain"])
    for f in found:
        good(f["subdomain"] + " -> " + f["ips"])
    summary = (
        str(len(found))
        + " subdomain(s) resolved of "
        + str(len(names))
        + " common name(s)"
    )
    return make_result(
        NAME, summary, found, {"resolved": len(found), "tried": len(names)}
    )
