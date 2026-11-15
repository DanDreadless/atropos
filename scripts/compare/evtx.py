"""Event log: Atropos against dissect.eventlog (Fox-IT) and python-evtx (Willi Ballenthin).

Usage: evtx.py EXPORT.jsonl FILE.evtx [EVIDENCE_ID]
Key: the event record number. Compared with dissect.eventlog: the time, the
event ID, the provider, the channel and the computer. Compared with
python-evtx: the time and the event ID.

Both libraries convert the FILETIME through a floating-point number, which at
this magnitude is good to two or three microseconds, so both are given that much
slack. To settle the exact value the script also reads each record's header
straight from the file (signature, size, record number, FILETIME) and
compares that with Atropos to the last 100 nanoseconds.
"""
import re
import struct
import sys

import Evtx.Evtx as pyevtx
from dissect.eventlog.evtx import Evtx

from common import load, ns, report, same_us

RECORD = bytes([0x2A, 0x2A, 0, 0])

export, path = sys.argv[1], sys.argv[2]
evid = int(sys.argv[3]) if len(sys.argv) > 3 else None
ours = {}
dupes = 0
for e in load(export, "evtx", evid):
    rid = e["fields"].get("record_id")
    dupes += rid in ours
    ours[rid] = e

bad = 0

# dissect.eventlog
theirs = {}
with open(path, "rb") as fh:
    for r in Evtx(fh):
        r = {k: (v.get() if hasattr(v, "sub_id") else v) for k, v in r.items()}
        theirs[r["EventRecordID"]] = r
diff = [f"{dupes} record numbers appear more than once in Atropos"] if dupes else []
for rid in sorted(set(ours) | set(theirs)):
    if rid not in ours:
        diff.append(f"record {rid}: missing from Atropos")
        continue
    if rid not in theirs:
        diff.append(f"record {rid}: only in Atropos")
        continue
    e, r = ours[rid], theirs[rid]
    f = e["fields"]
    if not same_us(e["ts_utc_ns"], ns(r["TimeCreated_SystemTime"]), 3):
        diff.append(f"record {rid}: time {e['ts_utc_ns']} here, {ns(r['TimeCreated_SystemTime'])} there")
    for name, mine, other in (("event id", str(f.get("event_id")), str(r["EventID"])),
                              ("provider", f.get("provider"), r.get("Provider_Name")),
                              ("channel", f.get("channel"), r.get("Channel")),
                              ("computer", e["host"], r.get("Computer"))):
        if mine != other:
            diff.append(f"record {rid}: {name} {mine!r} here, {other!r} there")
bad += report("Event log", "dissect.eventlog", path, f"{len(ours)} records", f"{len(theirs)} records", diff)

# python-evtx
theirs = {}
with pyevtx.Evtx(path) as log:
    for r in log.records():
        m = re.search(r"<EventID[^>]*>(\d+)</EventID>", r.xml())
        theirs[r.record_num()] = (ns(r.timestamp()), m.group(1) if m else None)
diff = []
unread = 0
for rid in sorted(set(ours) | set(theirs)):
    if rid not in ours:
        diff.append(f"record {rid}: missing from Atropos")
    elif rid not in theirs:
        unread += 1
    else:
        e, (t, eid) = ours[rid], theirs[rid]
        if not same_us(e["ts_utc_ns"], t, 3):
            diff.append(f"record {rid}: time {e['ts_utc_ns']} here, {t} there")
        if str(e["fields"].get("event_id")) != str(eid):
            diff.append(f"record {rid}: event id {e['fields'].get('event_id')} here, {eid} there")
notes = []
if unread:
    notes.append(f"{unread} records here were not returned by python-evtx, which reads only the chunks the file header counts; "
                 "the two checks either side of this one cover them")
bad += report("Event log", "python-evtx", path, f"{len(ours)} records", f"{len(theirs)} records", diff, notes)

# The record headers themselves.
raw = {}
data = open(path, "rb").read()
i = data.find(RECORD)
while i >= 0:
    if i + 28 <= len(data):
        size, rid, ft = struct.unpack_from("<IQQ", data, i + 4)
        if 28 <= size <= 0x10000 and i + size <= len(data) and struct.unpack_from("<I", data, i + size - 4)[0] == size:
            raw.setdefault(rid, (ft - 116444736000000000) * 100)
    i = data.find(RECORD, i + 4)
diff = []
for rid, e in sorted(ours.items()):
    if rid not in raw:
        diff.append(f"record {rid}: no header found in the file")
    elif raw[rid] != e["ts_utc_ns"]:
        diff.append(f"record {rid}: time {e['ts_utc_ns']} here, {raw[rid]} in the header")
bad += report("Event log, exact times", "the record headers, read directly", path, f"{len(ours)} records",
              f"{len(raw)} headers, including any left in unused space", diff)
sys.exit(1 if bad else 0)
