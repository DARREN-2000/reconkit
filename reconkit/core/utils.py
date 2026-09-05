import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

_USE_COLOR = sys.stdout.isatty()
_CODES = {
    "green": "32",
    "red": "31",
    "yellow": "33",
    "blue": "34",
    "cyan": "36",
    "gray": "90",
    "bold": "1",
}


def color(text, name):
    code = _CODES.get(name)
    if not _USE_COLOR or not code:
        return text
    return "\033[" + code + "m" + text + "\033[0m"


def info(msg):
    print(color("[*]", "blue") + " " + str(msg))


def good(msg):
    print(color("[+]", "green") + " " + str(msg))


def warn(msg):
    print(color("[!]", "yellow") + " " + str(msg))


def err(msg):
    print(color("[x]", "red") + " " + str(msg))


def make_result(module, summary, findings=None, data=None):
    return {
        "module": module,
        "summary": summary,
        "findings": findings or [],
        "data": data or {},
    }


def thread_map(func, items, workers):
    out = []
    if not items:
        return out
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(func, it) for it in items]
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res is not None:
                out.append(res)
    return out


def base_url(target, default_scheme="http"):
    t = (target or "").strip()
    if not t.startswith(("http://", "https://")):
        t = default_scheme + "://" + t
    return t.rstrip("/")


def mask(value, keep=4):
    s = str(value)
    if len(s) <= keep * 2:
        return s[:1] + "***"
    return s[:keep] + "***" + s[-keep:]
