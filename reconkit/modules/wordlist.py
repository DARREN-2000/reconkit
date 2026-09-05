import re
from collections import Counter
from html.parser import HTMLParser

from ..core.utils import base_url, good, make_result

NAME = "wordlist"
DESCRIPTION = "Builds a target-specific wordlist from page content (CeWL-like)"

_WORD = re.compile("[A-Za-z]{4,20}")
_STOP = set(
    [
        "this",
        "that",
        "with",
        "from",
        "your",
        "have",
        "will",
        "more",
        "about",
        "which",
        "their",
        "there",
        "would",
        "could",
        "should",
        "where",
        "when",
        "what",
        "your",
        "yours",
        "been",
        "being",
        "both",
        "each",
        "into",
        "then",
        "than",
        "they",
        "them",
        "http",
        "https",
        "www",
        "com",
    ]
)


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def run(target, ctx):
    base = base_url(target)
    resp = ctx.http.get(base)
    if resp is None or not resp.text:
        return make_result(NAME, "no response from target", [], {})
    tp = _Text()
    try:
        tp.feed(resp.text)
    except Exception:
        pass
    counts = Counter()
    for w in _WORD.findall(" ".join(tp.parts)):
        lw = w.lower()
        if lw not in _STOP:
            counts[lw] += 1
    top_n = int(ctx.options.get("top_words", 40) or 40)
    top = counts.most_common(top_n)
    out_path = ctx.options.get("out_wordlist", "")
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(w for w, _ in top) + "\n")
            good("wordlist written: " + out_path)
        except Exception:
            pass
    findings = [{"word": w, "count": c} for w, c in top]
    summary = str(len(findings)) + " candidate word(s) from page content"
    return make_result(
        NAME, summary, findings, {"unique_words": len(counts), "top": len(findings)}
    )
