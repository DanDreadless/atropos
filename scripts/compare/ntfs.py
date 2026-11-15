"""File table: Atropos against dissect.ntfs (Fox-IT).

Usage: ntfs.py EXPORT.jsonl VOLUME.dd [EVIDENCE_ID]
Key: the file record number and sequence. Compared, to the last 100
nanoseconds: the four $STANDARD_INFORMATION times of every record; every
$FILE_NAME time Atropos shows, against the $FILE_NAME attributes of the same
record; and the path, whether it is a directory, and the names of its
alternate data streams.

Atropos writes one event per distinct moment, lettered M, A, C, B for the
times that fall on it, so the four times are rebuilt from the letters.
"""
import sys

from dissect.ntfs import NTFS

from common import load, report

export, path = sys.argv[1], sys.argv[2]
evid = int(sys.argv[3]) if len(sys.argv) > 3 else None

LETTERS = {"M": "modified", "A": "accessed", "C": "changed", "B": "born"}
ours = {}
for e in load(export, "mft", evid):
    f = e["fields"]
    rec = ours.setdefault((f["entry"], f["sequence"]), {"si": {}, "fn": [], "path": e["path"], "is_dir": f.get("is_dir"),
                                                        "streams": sorted(x["name"] for x in f.get("streams") or []), "in_use": f.get("in_use")})
    kind = e["timestamp_desc"].split(" ")[0]
    for letter in e["macb"]:
        if letter in LETTERS:
            if kind == "$SI":
                rec["si"][LETTERS[letter]] = e["ts_utc_ns"]
            elif kind == "$FN":
                rec["fn"].append((LETTERS[letter], e["ts_utc_ns"]))

theirs = {}
fs = NTFS(open(path, "rb"))
for r in fs.mft.segments():
    try:
        si = r.attributes.STANDARD_INFORMATION[0].attribute
    except Exception:
        continue
    fns = []
    for a in r.attributes.get(0x30, []) if hasattr(r.attributes, "get") else r.attributes.FILE_NAME:
        fn = a.attribute
        fns.append({"modified": fn.last_modification_time_ns, "accessed": fn.last_access_time_ns,
                    "changed": fn.last_change_time_ns, "born": fn.creation_time_ns})
    streams = sorted({a.name for a in r.attributes.get(0x80, []) if a.name}) if hasattr(r.attributes, "get") else []
    try:
        full = "/" + r.full_path().replace("\\", "/")
    except Exception:
        full = None
    theirs[(r.segment, r.header.SequenceNumber)] = {
        "si": {"modified": si.last_modification_time_ns, "accessed": si.last_access_time_ns,
               "changed": si.last_change_time_ns, "born": si.creation_time_ns},
        "fn": fns, "path": full, "is_dir": r.is_dir(), "streams": streams, "in_use": bool(r.header.Flags & 1)}

diff = []
times = 0
unnamed = 0
for key in sorted(set(ours) | set(theirs)):
    name = f"record {key[0]}-{key[1]}"
    if key not in ours:
        if not theirs[key]["fn"]:
            unnamed += 1  # a reserved record with times and no name: not a file
        else:
            diff.append(f"{name}: missing from Atropos ({theirs[key]['path']})")
        continue
    if key not in theirs:
        diff.append(f"{name}: only in Atropos ({ours[key]['path']})")
        continue
    a, b = ours[key], theirs[key]
    for which in ("modified", "accessed", "changed", "born"):
        times += 1
        if a["si"].get(which) != b["si"][which]:
            diff.append(f"{name}: $SI {which} {a['si'].get(which)} here, {b['si'][which]} there")
    for which, t in a["fn"]:
        times += 1
        if not any(fn[which] == t for fn in b["fn"]):
            diff.append(f"{name}: $FN {which} {t} here matches no $FILE_NAME attribute there")
    if b["path"] is not None and a["path"].rstrip("/.") != b["path"].rstrip("/.") and b["in_use"]:
        diff.append(f"{name}: path {a['path']!r} here, {b['path']!r} there")
    if a["is_dir"] != b["is_dir"]:
        diff.append(f"{name}: directory {a['is_dir']} here, {b['is_dir']} there")
    if a["streams"] != b["streams"]:
        diff.append(f"{name}: streams {a['streams']} here, {b['streams']} there")
sys.exit(1 if report("File table", "dissect.ntfs", path, f"{len(ours)} records", f"{len(theirs)} records", diff,
                     [f"{times} times compared exactly",
                      f"{unnamed} records there have no $FILE_NAME (reserved file-table entries) and are not shown by Atropos"]) else 0)
