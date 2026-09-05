import argparse
import time
from datetime import datetime, timezone

from . import __version__
from .core import arsenal as arsenalmod
from .core import report as reportmod
from .core.http import HttpClient
from .core.registry import GROUPS, MODULES, resolve_modules
from .core.scope import RateLimiter, Scope, host_of, require_authorization
from .core.utils import color, err, good, info


class Context:
    def __init__(self, args, scope):
        self.workers = args.workers
        self.timeout = args.timeout
        self.scope = scope
        self.rate = RateLimiter(args.rate)
        self.options = {
            "ports": getattr(args, "ports", ""),
            "udp_ports": getattr(args, "udp_ports", ""),
            "wordlist": getattr(args, "wordlist", ""),
            "sub_wordlist": getattr(args, "sub_wordlist", ""),
            "param_wordlist": getattr(args, "param_wordlist", ""),
            "max_pages": getattr(args, "max_pages", 25),
            "tls_port": getattr(args, "tls_port", 0),
            "out_wordlist": getattr(args, "out_wordlist", ""),
            "top_words": getattr(args, "top_words", 40),
            "cookie": getattr(args, "cookie", ""),
            "auth_header": getattr(args, "auth_header", ""),
            "user_agent": getattr(args, "user_agent", ""),
            "creds": getattr(args, "creds", ""),
            "insecure": getattr(args, "insecure", False),
        }
        self.http = HttpClient(self)


def _banner():
    return (
        color("reconkit", "green")
        + color(" v" + __version__, "gray")
        + " - offensive recon platform (authorized use only)"
    )


def build_parser():
    p = argparse.ArgumentParser(
        prog="reconkit",
        description="Modular offensive-security recon platform. Authorized targets only.",
    )
    p.add_argument("--version", action="version", version="reconkit " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available modules and groups")

    r = sub.add_parser("run", help="run recon modules against a target")
    r.add_argument("target", help="host, IP, or URL you are authorized to test")
    sel = r.add_mutually_exclusive_group()
    sel.add_argument(
        "-m", "--modules", default="", help="comma list, e.g. ports,dirs,tls"
    )
    sel.add_argument("-g", "--group", choices=sorted(GROUPS), help="a module group")
    r.add_argument(
        "--authorized", action="store_true", help="attest authorization (skips prompt)"
    )
    r.add_argument(
        "--insecure", action="store_true", help="disable TLS verification"
    )
    r.add_argument(
        "--scope",
        action="append",
        default=[],
        help="extra in-scope host/domain (repeatable)",
    )
    r.add_argument("-w", "--workers", type=int, default=100)
    r.add_argument("-t", "--timeout", type=float, default=4.0)
    r.add_argument(
        "--rate", type=float, default=0.0, help="max requests/sec (0 = unlimited)"
    )
    r.add_argument(
        "--json", dest="json_out", default="", help="write JSON report to FILE"
    )
    r.add_argument(
        "--html", dest="html_out", default="", help="write HTML report to FILE"
    )
    r.add_argument(
        "--md",
        dest="md_out",
        default="",
        help="write Markdown engagement notes to FILE",
    )
    r.add_argument(
        "-p", "--ports", default="", help="ports for the ports module, e.g. 1-1024"
    )
    r.add_argument(
        "--udp-ports",
        dest="udp_ports",
        default="",
        help="ports for the udp module, e.g. 53,123,161",
    )
    r.add_argument("-W", "--wordlist", default="", help="wordlist file for dirs")
    r.add_argument(
        "--sub-wordlist",
        dest="sub_wordlist",
        default="",
        help="wordlist file for subdomains/subbrute",
    )
    r.add_argument(
        "--param-wordlist",
        dest="param_wordlist",
        default="",
        help="wordlist file for params",
    )
    r.add_argument(
        "--max-pages", dest="max_pages", type=int, default=25, help="spider page cap"
    )
    r.add_argument(
        "--tls-port",
        dest="tls_port",
        type=int,
        default=0,
        help="TLS port (default 443)",
    )
    r.add_argument(
        "--out-wordlist",
        dest="out_wordlist",
        default="",
        help="write generated wordlist to FILE",
    )
    r.add_argument("--top-words", dest="top_words", type=int, default=40)
    r.add_argument(
        "--cookie", default="", help="Cookie header value for authenticated scans"
    )
    r.add_argument(
        "--auth-header",
        dest="auth_header",
        default="",
        help="extra header, e.g. 'Authorization: Bearer TOKEN'",
    )
    r.add_argument(
        "--user-agent",
        dest="user_agent",
        default="",
        help="override the User-Agent string",
    )
    r.add_argument(
        "--creds",
        default="",
        help="extra default creds to try, e.g. admin:admin,root:toor",
    )

    a = sub.add_parser(
        "arsenal", help="catalog + detect + launch the wider legal offensive toolset"
    )
    asub = a.add_subparsers(dest="arsenal_cmd", required=True)
    al = asub.add_parser("list", help="list catalogued tools (optionally filtered)")
    al.add_argument("-c", "--category", default="", help="filter by category")
    al.add_argument(
        "--phase", type=int, default=0, help="filter by kill-chain phase 1-7"
    )
    al.add_argument(
        "--license", default="", help="filter: foss/freemium/commercial/reference"
    )
    ac = asub.add_parser(
        "check", help="detect which catalogued tools are installed here"
    )
    ac.add_argument(
        "-c", "--category", default="", help="limit the check to one category"
    )
    ar = asub.add_parser("run", help="launch an installed tool (authorized scope only)")
    ar.add_argument("tool", help="tool name, e.g. nmap")
    ar.add_argument(
        "--authorized",
        action="store_true",
        help="attest you are authorized to run this",
    )
    ar.add_argument(
        "--timeout", type=float, default=120.0, help="max seconds to let the tool run"
    )
    ar.add_argument(
        "toolargs", nargs=argparse.REMAINDER, help="args passed through to the tool"
    )
    return p


def cmd_list():
    print(_banner())
    print("\nModules (" + str(len(MODULES)) + "):")
    for name, mod in MODULES.items():
        print("  " + color(name.ljust(13), "cyan") + mod.DESCRIPTION)
    print("\nGroups:")
    for g, names in GROUPS.items():
        print("  " + color(g.ljust(13), "cyan") + ", ".join(names))
    return 0


def cmd_run(args):
    print(_banner())
    require_authorization(args.authorized)
    scope = Scope([host_of(args.target)] + list(args.scope))
    ctx = Context(args, scope)
    names = resolve_modules(args.modules, args.group)
    info("Target: " + args.target + "  |  scope: " + ", ".join(scope.as_list()))
    info("Modules: " + ", ".join(names))
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    results = []
    for name in names:
        mod = MODULES[name]
        print("\n" + color("== " + name + " ==", "bold") + " " + mod.DESCRIPTION)
        try:
            res = mod.run(args.target, ctx)
        except Exception as e:
            res = {
                "module": name,
                "summary": "error: " + type(e).__name__ + ": " + str(e),
                "findings": [],
                "data": {},
            }
            err(name + " failed: " + str(e))
        info(res.get("summary", ""))
        results.append(res)
    elapsed = round(time.time() - t0, 2)
    print("\n" + color("== summary ==", "bold"))
    for res in results:
        print(
            "  "
            + res["module"].ljust(13)
            + str(len(res.get("findings", []))).rjust(4)
            + "  "
            + res.get("summary", "")
        )
    info("Done in " + str(elapsed) + "s")
    rep = reportmod.build_report(
        args.target,
        results,
        {"version": __version__, "scope": scope.as_list(), "started": started},
    )
    rep["elapsed_seconds"] = elapsed
    if args.json_out:
        reportmod.write_json(args.json_out, rep)
        good("JSON report: " + args.json_out)
    if args.html_out:
        reportmod.write_html(args.html_out, rep)
        good("HTML report: " + args.html_out)
    if getattr(args, "md_out", ""):
        reportmod.write_markdown(args.md_out, rep)
        good("Markdown notes: " + args.md_out)
    return 0


def cmd_arsenal(args):
    print(_banner())
    sub = args.arsenal_cmd
    if sub == "list":
        entries = arsenalmod.filter_tools(
            category=args.category, phase=args.phase, license=args.license
        )
        s = arsenalmod.summary()
        print(
            "Arsenal: "
            + str(s["total"])
            + " legal offensive tools in "
            + str(len(s["categories"]))
            + " categories"
        )
        if args.category or args.phase or args.license:
            print("Filter -> " + str(len(entries)) + " match(es)")
        print(arsenalmod.format_list(entries))
        print("\nRun 'reconkit arsenal check' to see which are installed here.")
        return 0
    if sub == "check":
        res = arsenalmod.check(category=args.category)
        print(arsenalmod.format_check(res))
        print("\n" + res["summary"])
        return 0
    if sub == "run":
        toolargs = list(args.toolargs or [])
        if toolargs and toolargs[0] == "--":
            toolargs = toolargs[1:]
        res = arsenalmod.run_tool(
            args.tool, toolargs, authorized=args.authorized, timeout=args.timeout
        )
        info(res.get("summary", ""))
        for line in res.get("findings", []):
            print("  " + str(line))
        return 0 if res.get("data", {}).get("ok") else 1
    return 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "list":
        return cmd_list()
    if args.command == "run":
        return cmd_run(args)
    if args.command == "arsenal":
        return cmd_arsenal(args)
    return 1
