import socket

from ..core.scope import host_of, is_ip
from ..core.utils import good, info, make_result, thread_map

NAME = "subbrute"
DESCRIPTION = "Subdomain brute-force with wildcard detection"

DEFAULT_SUBS = [
    "www",
    "mail",
    "webmail",
    "smtp",
    "pop",
    "imap",
    "ns1",
    "ns2",
    "dns",
    "vpn",
    "remote",
    "api",
    "api-dev",
    "dev",
    "staging",
    "stage",
    "test",
    "qa",
    "uat",
    "beta",
    "demo",
    "portal",
    "admin",
    "administrator",
    "cpanel",
    "webdisk",
    "autodiscover",
    "m",
    "mobile",
    "app",
    "apps",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "files",
    "ftp",
    "sftp",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "jira",
    "confluence",
    "wiki",
    "docs",
    "support",
    "help",
    "status",
    "monitor",
    "grafana",
    "kibana",
    "db",
    "database",
    "sql",
    "mysql",
    "redis",
    "cache",
    "internal",
    "intranet",
    "corp",
    "secure",
    "login",
    "sso",
    "auth",
    "id",
    "account",
    "dashboard",
    "console",
    "manage",
    "backup",
    "old",
    "new",
    "shop",
    "store",
    "pay",
    "billing",
    "blog",
    "news",
    "email",
    "mx",
]


def _load_words(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [w.strip() for w in fh if w.strip() and not w.startswith("#")]
    except Exception:
        return []


def _resolve(name):
    try:
        infos = socket.getaddrinfo(name, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def run(target, ctx):
    domain = host_of(target)
    if not domain or is_ip(domain):
        return make_result(
            NAME, "target is an IP or empty; subdomain brute-force skipped", [], {}
        )
    wl = ctx.options.get("sub_wordlist", "")
    words = _load_words(wl) if wl else list(DEFAULT_SUBS)

    rand = "rk-nope-8x3k9q2z7"
    wildcard_ips = set(_resolve(rand + "." + domain))
    if wildcard_ips:
        info(
            "wildcard DNS detected ("
            + ", ".join(sorted(wildcard_ips))
            + "); filtering matches"
        )

    candidates = [w + "." + domain for w in words]

    def check(name):
        ips = _resolve(name)
        if not ips:
            return None
        if wildcard_ips and set(ips) == wildcard_ips:
            return None
        return {"subdomain": name, "ips": ", ".join(ips)}

    found = thread_map(check, candidates, min(ctx.workers, 50))
    found.sort(key=lambda f: f["subdomain"])
    for f in found:
        good(f["subdomain"] + " -> " + f["ips"])
    summary = (
        str(len(found)) + " subdomain(s) resolved of " + str(len(candidates)) + " tried"
    )
    return make_result(
        NAME,
        summary,
        found,
        {"tested": len(candidates), "wildcard": bool(wildcard_ips)},
    )
