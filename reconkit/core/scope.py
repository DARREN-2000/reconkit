import sys
import threading
import time
from urllib.parse import urlparse


class RateLimiter:
    def __init__(self, rate):
        self.interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                time.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + self.interval


def host_of(target):
    t = (target or "").strip()
    if "://" not in t:
        t = "//" + t
    parsed = urlparse(t)
    if parsed.hostname:
        return parsed.hostname.lower().rstrip(".")
    netloc = parsed.netloc or parsed.path
    host = netloc.split("@")[-1]
    if host.startswith("[") and "]" in host:
        host = host[1:host.find("]")]
    else:
        host = host.split(":")[0]
    return host.lower().rstrip(".")


def is_ip(host):
    parts = (host or "").split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in (host or "")


class Scope:
    def __init__(self, allowed=None):
        self.allowed = set()
        for a in allowed or []:
            self.add(a)

    def add(self, host):
        host = (host or "").lower().rstrip(".")
        if host:
            self.allowed.add(host)

    def allows(self, host):
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1"):
            return True
        for a in self.allowed:
            if host == a or host.endswith("." + a):
                return True
        return False

    def as_list(self):
        return sorted(self.allowed)


def require_authorization(authorized):
    if authorized:
        return
    print(
        "reconkit only runs against systems you own or are explicitly authorized to test."
    )
    try:
        answer = input("Type 'I am authorized' to continue: ").strip().lower()
    except EOFError:
        answer = ""
    if answer != "i am authorized":
        print(
            "Aborted. Use a lab, CTF, or in-scope bug-bounty target with written authorization."
        )
        sys.exit(2)
