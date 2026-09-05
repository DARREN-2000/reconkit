from ..core.utils import base_url, good, make_result, thread_map

NAME = "dirs"
DESCRIPTION = "HTTP(S) content and directory discovery"

DEFAULT_WORDS = [
    "admin",
    "administrator",
    "login",
    "logout",
    "dashboard",
    "api",
    "api/v1",
    "app",
    "assets",
    "backup",
    "backups",
    "config",
    "css",
    "data",
    "db",
    "debug",
    "dev",
    "docs",
    "downloads",
    "files",
    "images",
    "img",
    "js",
    "logs",
    "media",
    "old",
    "private",
    "public",
    "secret",
    "server-status",
    "static",
    "test",
    "tmp",
    "upload",
    "uploads",
    "user",
    "users",
    "wp-admin",
    "wp-content",
    ".git",
    ".env",
    ".svn",
    "phpinfo.php",
    "info.php",
    "robots.txt",
    "sitemap.xml",
]
INTERESTING = {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def _load(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [w.strip() for w in fh if w.strip() and not w.startswith("#")]
    except Exception:
        return []


def run(target, ctx):
    base = base_url(target)
    wl = ctx.options.get("wordlist", "")
    words = _load(wl) if wl else list(DEFAULT_WORDS)

    def probe(word):
        url = base + "/" + word.lstrip("/")
        resp = ctx.http.get(url, allow_redirects=False)
        if resp is None or resp.status not in INTERESTING:
            return None
        loc = (
            resp.headers.get("location", "")
            if resp.status in (301, 302, 307, 308)
            else ""
        )
        return {
            "path": "/" + word.lstrip("/"),
            "status": resp.status,
            "length": len(resp.body or b""),
            "location": loc,
        }

    found = thread_map(probe, words, min(ctx.workers, 30))
    found.sort(key=lambda f: f["path"])
    for f in found:
        good(str(f["status"]) + "  " + f["path"])
    summary = str(len(found)) + " interesting path(s) of " + str(len(words)) + " tried"
    return make_result(NAME, summary, found, {"found": len(found), "tried": len(words)})
