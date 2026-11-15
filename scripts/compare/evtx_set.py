"""Event logs in bulk: Atropos against EvtxECmd over a folder of logs.

Usage: evtx_set.py EXPORT.jsonl EVTXECMD.csv
       (EvtxECmd -d FOLDER --csv DIR --csvf all.csv; the export of a case
       holding the same folder)

Key: the file's name and the event record number. Compared: the time to
100 nanoseconds, the event ID, the provider, the channel and the computer.
Only the standard library is needed.
"""
import collections
import json
import sys

from ez import rows, same, t_ns
from common import report

export, path = sys.argv[1], sys.argv[2]
names = {}
ours = {}
for line in open(export, encoding="utf-8"):
    e = json.loads(line)
    if e["source"] != "evtx":
        continue
    ours[(e["evidence_id"], int(e["fields"]["record_id"]))] = e
# Evidence names come from the record reference's evidence; the export has
# no names, so they are matched through EvtxECmd's file names below.
by_file = collections.defaultdict(dict)
for (ev, rid), e in ours.items():
    by_file[ev][rid] = e

theirs = collections.defaultdict(dict)
for r in rows(path):
    name = r["SourceFile"].replace("/", "\\").split("\\")[-1]
    theirs[name][int(r["EventRecordId"])] = r

# Pair each evidence item with the EvtxECmd file whose record numbers it shares.
diff, compared, unpaired = [], 0, 0
used = set()
for ev, recs in sorted(by_file.items()):
    ids = set(recs)
    best = max(theirs, key=lambda n: (len(ids & set(theirs[n])) if n not in used else -1), default=None)
    if best is None or not ids & set(theirs[best]):
        unpaired += 1
        diff.append(f"evidence {ev}: no EvtxECmd file shares its record numbers")
        continue
    used.add(best)
    t = theirs[best]
    for rid in sorted(ids | set(t)):
        if rid not in recs or rid not in t:
            diff.append(f"{best} record {rid}: only in {'the other tool' if rid not in recs else 'Atropos'}")
            continue
        e, r = recs[rid], t[rid]
        compared += 1
        if not same(e["ts_utc_ns"], t_ns(r["TimeCreated"])):
            diff.append(f"{best} record {rid}: time {e['datetime_utc']} here, {r['TimeCreated']} there")
        for what, mine, other in (("event id", str(e["fields"].get("event_id")), r["EventId"]),
                                  ("provider", e["fields"].get("provider") or "", r["Provider"]),
                                  ("channel", e["fields"].get("channel") or "", r["Channel"]),
                                  ("computer", e["host"] or "", r["Computer"])):
            if mine != other:
                diff.append(f"{best} record {rid}: {what} {mine!r} here, {other!r} there")
for n in sorted(set(theirs) - used):
    diff.append(f"{n}: {len(theirs[n])} records, not paired with any Atropos evidence (a duplicate file is parsed once)")
sys.exit(1 if report("Event logs (folder)", "EvtxECmd", path, f"{len(ours)} records in {len(by_file)} logs",
                     f"{sum(map(len, theirs.values()))} records in {len(theirs)} logs; {compared} compared", diff) else 0)
