from ..core.utils import base_url, make_result, warn

NAME = "misconfig"
DESCRIPTION = "Checks for common sensitive file and directory exposures"

SENSITIVE = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.svn/entries",
    "/.hg/store",
    "/.DS_Store",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/.htaccess",
    "/server-status",
    "/phpinfo.php",
    "/.aws/credentials",
    "/id_rsa",
    "/.npmrc",
    "/composer.lock",
    "/web.config",
    "/.git-credentials",
]
DIR_LISTING = ["index of /", "directory listing for", "<title>index of"]


def run(target, ctx):
    base = base_url(target)
    findings = []
    for path in SENSITIVE:
        resp = ctx.http.get(base + path, allow_redirects=False)
        if resp is None:
            continue
        if resp.status == 200 and resp.body:
            warn("exposed: " + path + " (HTTP 200)")
            findings.append({"path": path, "status": 200, "issue": "accessible"})
    root = ctx.http.get(base + "/")
    if root is not None and any(s in root.text.lower() for s in DIR_LISTING):
        findings.append(
            {"path": "/", "status": root.status, "issue": "directory listing enabled"}
        )
    summary = (
        (str(len(findings)) + " exposure(s)")
        if findings
        else "no obvious sensitive-file exposure"
    )
    return make_result(NAME, summary, findings, {"exposed": len(findings)})
