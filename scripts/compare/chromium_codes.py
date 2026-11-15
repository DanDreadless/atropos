"""Chromium history codes: what Atropos calls each number against Hindsight (Ryan Benson).

Usage: chromium_codes.py PATH/TO/pyhindsight PATH/TO/internal/parsers/sqlite.go
No evidence is read. The tables are lifted from the two sources and printed
side by side, one line per code, so a person can judge whether the meanings
agree: the wording differs by design. Codes only one side knows are marked.
"""
import re
import sys

hind, ours = sys.argv[1], sys.argv[2]
chrome = open(hind + "/browsers/chrome.py", encoding="utf-8").read()
web = open(hind + "/browsers/webbrowser.py", encoding="utf-8").read()
go = open(ours, encoding="utf-8").read()


def py_table(src, func):
    """The number: 'text' pairs in the body of one method."""
    i = src.index("def " + func)
    j = src.find("\n        def ", i + 1)
    body = src[i:j if j > 0 else len(src)]
    out = {}
    for m in re.finditer(r"(0x[0-9A-Fa-f]+|\d+):\s*\(?\s*['\"]([^'\"]*)['\"]", body):
        out.setdefault(int(m.group(1), 0), m.group(2))
    return out


def go_table(name):
    i = go.index(name)
    j = go.index("}", go.index("{", i))
    return {int(m.group(1), 0): m.group(2) for m in re.finditer(r"(0x[0-9A-Fa-f]+|\d+):\s*\"([^\"]*)\"", go[i:j])}


pairs = [
    ("visit source (visit_source.source)", go_table("chromiumSources"), py_table(chrome, "decode_source")),
    ("download state", go_table("downloadStates "), py_table(chrome, "decode_download_state")),
    ("download danger type", go_table("downloadDangers "), py_table(chrome, "decode_danger_type")),
    ("download interrupt reason", go_table("downloadInterrupts "), py_table(chrome, "decode_interrupt_reason")),
]
for title, a, b in pairs:
    print(f"## {title}: {len(a)} here, {len(b)} there")
    for code in sorted(set(a) | set(b)):
        mark = "  " if code in a and code in b else ("<<" if code in a else ">>")
        print(f"{mark} {code:>4}  {a.get(code, '-'):<58} | {b.get(code, '-')}")
    print()

print("## page transition (webbrowser.py decode_transition, for reading beside chromiumVisits)")
i = web.index("def decode_transition")
print(web[i:web.find("\n        def ", i + 1)])
