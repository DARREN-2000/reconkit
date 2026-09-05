from ..modules import (
    cookies,
    cors,
    crtsh,
    defaultcreds,
    dirs,
    dns,
    fingerprint,
    headers,
    injection,
    misconfig,
    openredirect,
    params,
    ports,
    robots,
    secrets,
    spider,
    subbrute,
    subdomains,
    takeover,
    tls,
    udp,
    waf,
    wayback,
    whois,
    wordlist,
)

_MODS = [
    ports,
    udp,
    dns,
    subdomains,
    subbrute,
    tls,
    whois,
    crtsh,
    wayback,
    headers,
    fingerprint,
    robots,
    params,
    cookies,
    waf,
    dirs,
    misconfig,
    spider,
    wordlist,
    cors,
    openredirect,
    secrets,
    injection,
    takeover,
    defaultcreds,
]
MODULES = {m.NAME: m for m in _MODS}
GROUPS = {
    "net": ["ports", "udp", "dns", "subdomains", "subbrute", "tls"],
    "osint": ["whois", "crtsh", "wayback"],
    "web": [
        "headers",
        "fingerprint",
        "robots",
        "params",
        "cookies",
        "waf",
        "dirs",
        "misconfig",
        "spider",
        "wordlist",
    ],
    "vuln": [
        "cors",
        "openredirect",
        "secrets",
        "injection",
        "takeover",
        "defaultcreds",
    ],
    "passive": ["whois", "crtsh", "wayback", "dns"],
    "all": [m.NAME for m in _MODS],
}


def resolve_modules(spec_modules, group):
    if spec_modules:
        names = [s.strip() for s in spec_modules.split(",") if s.strip()]
    elif group:
        names = list(GROUPS.get(group, []))
    else:
        names = list(GROUPS["all"])
    unknown = [n for n in names if n not in MODULES]
    if unknown:
        raise SystemExit("Unknown module(s): " + ", ".join(unknown))
    return names
