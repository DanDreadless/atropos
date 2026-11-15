"""SRUM: Atropos against dissect.esedb (Fox-IT).

Usage: srum.py EXPORT.jsonl SRUDB.dat [EVIDENCE_ID]
Key: the table and the row's AutoIncId. Compared: that every row is present
once, its time, the application and account it names (resolved here from
SruDbIdMapTable independently), and the figures each table carries.
"""
import datetime
import re
import struct
import sys

from dissect.esedb import EseDB

from common import load, ns, report, same_us

export, path = sys.argv[1], sys.argv[2]
evid = int(sys.argv[3]) if len(sys.argv) > 3 else None

APP_USAGE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
NET_USAGE = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
NET_CONN = "{DD6636C4-8929-4683-974E-22C046A43763}"
ACTIVITY = "{5C8CF1C7-7257-4F13-B223-970EF5939312}"
# table: (how the event time is stored, [(field here, column there)])
TABLES = {
    APP_USAGE: ("ole", [("foreground_bytes_read", "ForegroundBytesRead"), ("foreground_bytes_written", "ForegroundBytesWritten"),
                        ("foreground_cycle_time", "ForegroundCycleTime"), ("face_time", "FaceTime")]),
    NET_USAGE: ("ole", [("bytes_sent", "BytesSent"), ("bytes_received", "BytesRecvd"), ("interface_luid", "InterfaceLuid")]),
    NET_CONN: ("ConnectStartTime", [("connected_seconds", "ConnectedTime"), ("interface_luid", "InterfaceLuid")]),
    ACTIVITY: ("EndTime", [("duration_ms", "DurationMS")]),
}


def ole(bits):
    """An OLE automation date, stored as the bits of a double: days since 30 December 1899."""
    days = struct.unpack("<d", struct.pack("<q", bits))[0]
    return ns(datetime.datetime(1899, 12, 30) + datetime.timedelta(days=days))


def filetime(v):
    return (v - 116444736000000000) * 100


def sid(b):
    if not b or len(b) < 8 or b[0] != 1 or len(b) != 8 + 4 * b[1]:
        return None
    auth = int.from_bytes(b[2:8], "big")
    subs = struct.unpack(f"<{b[1]}I", b[8:])
    return "S-1-" + "-".join(str(x) for x in (auth,) + subs)


db = EseDB(open(path, "rb"))
names = {}
for r in db.table("SruDbIdMapTable").records():
    blob = r.get("IdBlob")
    if blob is None:
        continue
    if r.get("IdType") == 3:
        names[r.get("IdIndex")] = sid(blob) or blob.hex()
    else:
        names[r.get("IdIndex")] = blob.decode("utf-16-le", "replace").rstrip("\x00")

ours = {}
dupes = 0
for e in load(export, "srum", evid):
    m = re.match(r"table (\{[0-9A-F-]+\}), AutoIncId (\d+)", e["record_ref"])
    key = (m.group(1), int(m.group(2)))
    dupes += key in ours
    ours[key] = e

diff = [f"{dupes} rows appear more than once in Atropos"] if dupes else []
rows = 0
unreadable = 0
checked = {"time": 0, "application": 0, "user": 0, "figure": 0}
for table, (when, figures) in TABLES.items():
    seen = set()
    for r in db.table(table).records():
        if r.get("AutoIncId") is None:
            unreadable += 1  # dissect returns a row it could not decode as all-empty
            continue
        rows += 1
        key = (table, r.get("AutoIncId"))
        seen.add(key)
        name = f"{table} row {key[1]}"
        e = ours.get(key)
        if e is None:
            diff.append(f"{name}: missing from Atropos")
            continue
        f = e["fields"]
        if when == "ole":
            ok = same_us(e["ts_utc_ns"], ole(r.get("TimeStamp")), 1000)  # a double of days is good to about a millisecond
            theirs_t = ole(r.get("TimeStamp"))
        else:
            theirs_t = filetime(r.get(when))
            ok = e["ts_utc_ns"] == theirs_t
        checked["time"] += 1
        if not ok:
            diff.append(f"{name}: time {e['ts_utc_ns']} here, {theirs_t} there")
        for mine, col, kind in (("application", "AppId", "application"), ("user", "UserId", "user")):
            want = names.get(r.get(col))
            if want is not None and mine in f:
                checked[kind] += 1
                # The activity table's identifier is shown as the program's name, with the stored form beside it.
                if (f.get("application_stored", f[mine]) if mine == "application" else f[mine]) != want:
                    diff.append(f"{name}: {mine} {f[mine]!r} here, {want!r} there")
        for mine, col in figures:
            if mine in f:
                checked["figure"] += 1
                if f[mine] != r.get(col):
                    diff.append(f"{name}: {mine} {f[mine]} here, {r.get(col)} there")
    for key in ours:
        if key[0] == table and key not in seen:
            diff.append(f"{table} row {key[1]}: only in Atropos")
other = {k[0] for k in ours} - set(TABLES)
if other:
    diff.append(f"Atropos has rows from tables not compared here: {sorted(other)}")
sys.exit(1 if report("SRUM", "dissect.esedb", path, f"{len(ours)} rows", f"{rows} rows in the four tables", diff,
                     [f"compared: {checked['time']} times, {checked['application']} application names, {checked['user']} accounts, {checked['figure']} figures",
                      f"{unreadable} rows there came back with no AutoIncId and no values, and are not counted"]) else 0)
