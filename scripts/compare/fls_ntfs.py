"""NTFS: Atropos's file-table events against The Sleuth Kit's fls.

    fls -r -p -m / VOLUME > body.txt        (or -o SECTOR for a partition)
    python fls_ntfs.py EXPORT.jsonl body.txt [EVIDENCE_ID]

Atropos may read the volume itself or the $MFT taken out of it (icat VOLUME 0).

Compared, MFT entry by entry: the path, whether the entry is deleted, and
both sets of times to the second (the body file has whole seconds):

- $STANDARD_INFORMATION: fls gives it on each stream's line; Atropos's "$SI"
  events must hold exactly those four times.
- $FILE_NAME: fls gives it on the "($FILE_NAME)" line. Atropos emits a "$FN"
  time only where it adds a moment $SI does not already show, so each fls
  $FILE_NAME time must be either Atropos's $FN time for that letter or one of
  the entry's $SI times, and every Atropos $FN time must be fls's.

Entries fls cannot reach by path (it lists them under /$OrphanFiles) are
compared by entry number all the same. Only the standard library is needed.
Differences name files from the evidence: keep the output out of the
repository unless the input is a public sample.
"""
import re
import sys
from collections import defaultdict

from common import load, report

if len(sys.argv) < 3:
    sys.exit(__doc__)
export, body = sys.argv[1], sys.argv[2]
evid = int(sys.argv[3]) if len(sys.argv) > 3 else None
LETTERS = "MACB"

# Atropos: per entry, its path and its $SI and $FN times by letter.
ours = defaultdict(lambda: {"path": None, "deleted": False, "SI": {}, "FN": {}})
for e in load(export, "mft", evid):
    attr = e["timestamp_desc"][:3].lstrip("$")
    if attr not in ("SI", "FN"):
        continue
    o = ours[e["fields"]["entry"]]
    o["path"], o["deleted"] = e["path"], not e["fields"].get("in_use", True)
    for i, letter in enumerate(LETTERS):
        if e["macb"][i] == letter:
            o[attr][letter] = e["ts_utc_ns"] // 10**9

# fls: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime, inode as ENTRY-TYPE-ID.
theirs = defaultdict(lambda: {"paths": set(), "deleted": False, "SI": None, "FN": None})
with open(body, encoding="utf-8", errors="replace") as f:
    for line in f:
        c = line.rstrip("\n").split("|")
        if len(c) < 11:
            continue
        m = re.match(r"(\d+)-(\d+)-\d+$", c[2])
        if not m:
            continue  # fls's own virtual entries ($OrphanFiles and the like)
        entry = int(m.group(1))
        name = c[1]
        deleted = name.endswith(" (deleted)")
        name = name.removesuffix(" (deleted)")
        fn = name.endswith(" ($FILE_NAME)")
        name = name.removesuffix(" ($FILE_NAME)")
        t = {"A": int(c[7]), "M": int(c[8]), "C": int(c[9]), "B": int(c[10])}
        t = {k: v for k, v in t.items() if v}
        o = theirs[entry]
        o["deleted"] |= deleted
        if fn:
            o["FN"] = t
        else:
            o["SI"] = t
            o["paths"].add(name.split(":", 1)[0])  # a named stream's line names its file

diffs = []
compared = fn_checked = fn_here = 0
for entry in sorted(set(ours) | set(theirs)):
    a, b = ours.get(entry), theirs.get(entry)
    if a is None:
        if b["SI"]:
            diffs.append(f"entry {entry} {sorted(b['paths'])}: listed by fls, not by Atropos")
        continue
    if (b is None or b["SI"] is None) and entry == 5:
        continue  # the root directory: fls -r lists what is in it, not the root itself
    if b is None or b["SI"] is None:
        diffs.append(f"entry {entry} {a['path']}: listed by Atropos, not by fls")
        continue
    compared += 1
    p = a["path"]
    if not any(x.lower() == p.lower() or x.lower().endswith("/" + p.rsplit("/", 1)[-1].lower()) for x in b["paths"]):
        diffs.append(f"entry {entry}: path {p} here, {sorted(b['paths'])} in fls")
    if a["deleted"] != b["deleted"]:
        diffs.append(f"entry {entry} {p}: deleted {a['deleted']} here, {b['deleted']} in fls")
    if a["SI"] != b["SI"]:
        diffs.append(f"entry {entry} {p}: $SI {a['SI']} here, {b['SI']} in fls")
    if b["FN"] is not None:
        si_times = set(a["SI"].values())
        for letter in LETTERS:
            want = b["FN"].get(letter)
            mine = a["FN"].get(letter)
            fn_checked += want is not None
            fn_here += mine is not None
            if mine is not None and mine != want:
                diffs.append(f"entry {entry} {p}: $FN {letter} {mine} here, {want} in fls")
            elif mine is None and want is not None and want not in si_times:
                diffs.append(f"entry {entry} {p}: $FN {letter} {want} in fls, not shown here")
    elif a["FN"]:
        diffs.append(f"entry {entry} {p}: $FN times here, none in fls")

n = report("NTFS file table", "The Sleuth Kit fls -m", body,
           f"{len(ours)} entries; {fn_here} $FN times shown apart from $SI",
           f"{len([e for e in theirs.values() if e['SI']])} entries ({compared} in both); {fn_checked} $FN times checked", diffs)
sys.exit(1 if n else 0)
