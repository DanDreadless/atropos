"""Atropos against Plaso over the same set of files: which times each has that the other lacks, per file and kind.

Usage: plaso.py PSORT.jsonl ATROPOS.jsonl CASE_DIR SOURCE_ROOT_ATROPOS SOURCE_ROOT_PLASO

  PSORT.jsonl    psort -o json_line -w PSORT.jsonl STORAGE.plaso   (log2timeline --single_process on the folder)
  ATROPOS.jsonl  atropos export --case CASE_DIR --format jsonl -o ATROPOS.jsonl
  CASE_DIR       the Atropos case, read only, to name each evidence item's file
  the two roots  where the same folder lies on each side, cut from the paths so the files can be paired

Plaso's file-system times (fs:stat) are the times of the copies the tools read, not evidence, and are left out.
A time is compared to the microsecond, Plaso's precision, with one microsecond either way (Plaso rounds a
100-nanosecond time to the nearest microsecond, and Atropos's is cut to it here), and matched against any Atropos event of the same file:
the comparison is of what is on each timeline, not of how each tool names it. Times of zero or before 1970
(Plaso's "Not a time") are left out. Differences name records from the evidence: keep the output out of the
repository unless the input is a public sample.
"""
import json
import sqlite3
import sys
from collections import Counter, defaultdict


def rel(path, root):
    p = path.replace("\\", "/")
    root = root.replace("\\", "/").rstrip("/") + "/"
    i = p.lower().find(root.lower())
    return p[i + len(root):].lower() if i >= 0 else None


def main(psort, export, case, root_ours, root_theirs):
    db = sqlite3.connect(f"file:{case}/case.db?mode=ro", uri=True)
    files = {i: rel(origin or name, root_ours) for i, name, origin in db.execute("SELECT id, name, origin FROM evidence")}
    ours = defaultdict(lambda: defaultdict(list))  # file -> microsecond -> kinds
    for line in open(export, encoding="utf-8"):
        e = json.loads(line)
        f = files.get(int(e["evidence_id"]))
        if f:
            ours[f][int(e["ts_utc_ns"]) // 1000].append(e["source"] + " " + e["timestamp_desc"])
    theirs = defaultdict(lambda: defaultdict(list))
    kinds = Counter()
    for line in open(psort, encoding="utf-8"):
        e = json.loads(line)
        if e.get("data_type") == "fs:stat":
            continue
        f = rel(e.get("filename") or e.get("display_name", "").split(":", 1)[-1], root_theirs)
        t = e.get("timestamp")
        if not f or not isinstance(t, int) or t <= 0:
            continue
        kind = f"{e.get('parser', '?')} / {e.get('data_type', '?')} / {e.get('timestamp_desc', '?')}"
        theirs[f][t].append(kind)
        kinds[kind] += 1
    only_theirs, only_ours, matched = Counter(), Counter(), Counter()
    example = {}
    per_file = Counter()
    for f in sorted(set(ours) | set(theirs)):
        o, t = ours.get(f, {}), theirs.get(f, {})
        near = lambda ts, side: ts in side or ts - 1 in side or ts + 1 in side
        for ts, ks in t.items():
            for k in ks:
                if near(ts, o):
                    matched[k] += 1
                else:
                    only_theirs[k] += 1
                    per_file[(f, k)] += 1
                    example.setdefault(k, (f, ts))
        for ts, ks in o.items():
            if not near(ts, t):
                for k in ks:
                    only_ours[k] += 1
    print("## Plaso against Atropos (times per file, to the microsecond)")
    print(f"files: {len(ours)} with Atropos events, {len(theirs)} with Plaso events (fs:stat left out)")
    print(f"Plaso events: {sum(kinds.values())}; with a time Atropos also has for that file: {sum(matched.values())}")
    print("\n### Plaso kinds, matched and not")
    for k in sorted(kinds, key=lambda k: -kinds[k]):
        f, ts = example.get(k, ("", 0))
        print(f"{kinds[k]:8d}  matched {matched[k]:7d}  not {only_theirs[k]:6d}  {k}" + (f"   e.g. {f} @ {ts}" if k in example else ""))
    print("\n### Files where Plaso has most times Atropos lacks")
    for (f, k), n in per_file.most_common(25):
        print(f"{n:7d}  {f}  {k}")
    print("\n### Atropos kinds with times Plaso lacks for the file")
    for k, n in only_ours.most_common(40):
        print(f"{n:8d}  {k}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
