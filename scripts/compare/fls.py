"""FAT, exFAT and ext2/3/4 volumes: Atropos against The Sleuth Kit's fls.

    fls -r -p -m / -z UTC [-o SECTOR_OFFSET] IMAGE > body.txt
    python fls.py fat|ext EXPORT.jsonl body.txt [EVIDENCE_ID] [PARTITION]

Run fls on the volume itself, or with -o set to the partition's first sector
(mmls lists them) and PARTITION set to the name Atropos gives it ("p1").
`-z UTC` makes fls read FAT's zoneless local times as UTC, which is what
Atropos does when the case has no host zone: run Atropos the same way.
ext times are UTC whatever the zone.

Compared, path by path: whether the entry is present, deleted or not, its
size, and its modified, accessed, changed (ext) and created times to the
second (the body file has whole seconds; a FAT access time is a day). For
ext, deleted names whose inode now belongs to another file are left out by
Atropos and flagged "(realloc)" by fls; such lines are skipped. Only the standard
library is needed. Differences name files from the evidence: keep the output
out of the repository unless the input is a public sample.
"""
import sys
from collections import defaultdict

from common import load, report

if len(sys.argv) < 4 or sys.argv[1] not in ("fat", "ext"):
    sys.exit(__doc__)
kind, export, body = sys.argv[1], sys.argv[2], sys.argv[3]
evid = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None
part = "/" + sys.argv[5] if len(sys.argv) > 5 else ""
letters = (("M", 0), ("A", 1), ("C", 2), ("B", 3)) if kind == "ext" else (("M", 0), ("A", 1), ("B", 3))

# Atropos: one entry per path, its times keyed by MACB letter.
ours = defaultdict(lambda: {"times": {}, "deleted": False, "size": None, "dir": False, "target": None})
for e in load(export, kind, evid):
    if e["macb"] == "":
        continue  # an ext inode's deletion time: fls's body file has no column for it
    p = e["path"]
    if part:
        if not p.startswith(part + "/"):
            continue
        p = p[len(part):]
    o = ours[p.lower()]
    f = e["fields"]
    o["path"], o["size"], o["deleted"] = p, f.get("size"), bool(f.get("deleted"))
    o["dir"] = bool(f.get("is_dir")) or f.get("type") == "directory"
    o["target"] = f.get("link_target")
    for letter, i in letters:
        if e["macb"][i] == letter:
            o["times"][letter] = e["ts_utc_ns"] // 10**9

# fls: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
theirs = {}
with open(body, encoding="utf-8", errors="replace") as f:
    for line in f:
        c = line.rstrip("\n").split("|")
        if len(c) < 11:
            continue
        name = c[1]
        if name.endswith("(realloc)"):
            continue
        deleted = name.endswith(" (deleted)")
        name = name.removesuffix(" (deleted)")
        # fls names a symbolic link "name -> target".
        target = None
        if " -> " in name:
            name, target = name.split(" -> ", 1)
        base = name.rsplit("/", 1)[-1]
        # fls also lists what is not a file: the volume label, the FAT
        # tables, the boot sector and "." entries.
        if base in (".", "..") or name.startswith("/$") or "(Volume Label Entry)" in name or name.endswith("/$OrphanFiles"):
            continue
        theirs[name.lower()] = {"path": name, "deleted": deleted, "size": int(c[6]), "target": target,
                                "times": {"A": int(c[7]), "M": int(c[8]), "C": int(c[9]), "B": int(c[10])}}

diffs = []
for k in sorted(set(ours) | set(theirs)):
    a, b = ours.get(k), theirs.get(k)
    if a is None:
        diffs.append(f"{b['path']}: listed by fls{' (deleted)' if b['deleted'] else ''}, not by Atropos")
        continue
    if b is None:
        diffs.append(f"{a['path']}: listed by Atropos{' (deleted)' if a['deleted'] else ''}, not by fls")
        continue
    if a["deleted"] != b["deleted"]:
        diffs.append(f"{a['path']}: deleted {a['deleted']} here, {b['deleted']} in fls")
    # A directory's size is left at 0 here on purpose; fls gives its data's size.
    if not a["dir"] and a["size"] is not None and a["size"] != b["size"] and b["size"] != 0:
        diffs.append(f"{a['path']}: size {a['size']} here, {b['size']} in fls")
    if b["target"] is not None and a["target"] != b["target"]:
        diffs.append(f"{a['path']}: link target {a['target']!r} here, {b['target']!r} in fls")
    for letter, _ in letters:
        mine, other = a["times"].get(letter), b["times"].get(letter) or None
        if mine != other:
            diffs.append(f"{a['path']}: {letter} {mine} here, {other} in fls")

n = report(f"{kind} names and times", "The Sleuth Kit fls -m", body,
           f"{len(ours)} entries", f"{len(theirs)} entries", diffs)
sys.exit(1 if n else 0)
