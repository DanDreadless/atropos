"""Atropos against Eric Zimmerman's tools, from their CSV output.

Usage: ez.py KIND EXPORT.jsonl CSV_OR_FOLDER [EVIDENCE_ID]

  evtx       EvtxECmd -f LOG --csv DIR --csvf out.csv
  prefetch   PECmd -d DIR --csv DIR --csvf out.csv         (the main CSV, not the timeline)
  srum       SrumECmd -f SRUDB.dat --csv DIR               (pass the folder)
  mft        MFTECmd -f $MFT --csv DIR --csvf out.csv
  shimcache  AppCompatCacheParser -f SYSTEM --csv DIR --csvf out.csv
  shellbags  SBECmd -d DIR_WITH_HIVES --csv DIR            (pass the hive's CSV)
  recycle    RBCmd -d DIR --csv DIR --csvf out.csv
  recmd      RECmd -d DIR --bn BatchExamples/DFIRBatch.reb --csv DIR   (pass its CSV, and the hive's evidence id)
  jumplist   JLECmd -d DIR --csv DIR                       (pass the AutomaticDestinations CSV)

Only the standard library is needed. Times are compared to the precision the
tool writes: 100 nanoseconds where its CSV has seven decimal places, whole
seconds where it has none (the tool cuts, it does not round). Each comparison
exits non-zero on a difference. Differences name records from the evidence:
keep the output out of the repository unless the input is a public sample.
"""
import csv
import glob
import os
import re
import sys
from collections import defaultdict

from common import load, report

csv.field_size_limit(1 << 30)


def rows(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def t_ns(s):
    """'2019-02-06 14:17:53.3172597' as nanoseconds since 1970, and the number of decimal places."""
    s = s.strip()
    if not s:
        return None, 0
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:\.(\d+))?", s)
    if not m:
        return None, 0
    import datetime
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    days = (datetime.date(y, mo, d) - datetime.date(1970, 1, 1)).days
    frac = m.group(7) or ""
    return (days * 86400 + h * 3600 + mi * 60 + se) * 10**9 + int((frac + "000000000")[:9] or 0), len(frac)


def same(ours_ns, theirs):
    """Our time against a parsed tool time, at the tool's precision."""
    t, places = theirs
    if t is None:
        return False
    unit = 10 ** (9 - min(places, 9))
    return ours_ns // unit == t // unit


def evtx(export, path, evid):
    ours = {e["fields"].get("record_id"): e for e in load(export, "evtx", evid)}
    theirs = {int(r["EventRecordId"]): r for r in rows(path)}
    diff = []
    for rid in sorted(set(ours) | set(theirs)):
        if rid not in ours or rid not in theirs:
            diff.append(f"record {rid}: only in {'the other tool' if rid not in ours else 'Atropos'}")
            continue
        e, r = ours[rid], theirs[rid]
        if not same(e["ts_utc_ns"], t_ns(r["TimeCreated"])):
            diff.append(f"record {rid}: time {e['datetime_utc']} here, {r['TimeCreated']} there")
        for name, mine, other in (("event id", str(e["fields"].get("event_id")), r["EventId"]),
                                  ("provider", e["fields"].get("provider"), r["Provider"]),
                                  ("channel", e["fields"].get("channel"), r["Channel"]),
                                  ("computer", e["host"], r["Computer"])):
            if (mine or "") != (other or ""):
                diff.append(f"record {rid}: {name} {mine!r} here, {other!r} there")
    return report("Event log", "EvtxECmd", path, f"{len(ours)} records", f"{len(theirs)} records", diff)


def prefetch(export, path, evid):
    # Several files can share a program name and path hash (the same program on
    # different systems), so a file is keyed by those and its last run.
    files = defaultdict(lambda: {"times": set()})
    for e in load(export, "prefetch", evid):
        f = files[e["evidence_id"]]
        f["times"].add(e["ts_utc_ns"] // 10**9)
        f["exe"], f["count"] = e["fields"]["executable"].upper(), e["fields"].get("run_count")
        # The other tool prints the hash without leading zeros.
        f["hash"] = e["fields"]["prefetch_hash"].upper().replace("0X", "").lstrip("0")
    ours = {(f["exe"], f["hash"], max(f["times"])): f for f in files.values()}
    theirs, failed = {}, 0
    for r in rows(path):
        if r.get("ParsingError", "").lower() == "true" or not r["ExecutableName"]:
            failed += 1
            continue
        times = set()
        for col in ["LastRun"] + [f"PreviousRun{i}" for i in range(7)]:
            t, _ = t_ns(r[col])
            if t is not None:
                times.add(t // 10**9)
        if times:
            theirs[(r["ExecutableName"].upper(), r["Hash"].upper().lstrip("0"), max(times))] = {"times": times, "count": r["RunCount"]}
    diff = []
    for key in sorted(set(ours) | set(theirs)):
        if key not in ours or key not in theirs:
            diff.append(f"{key}: only in {'the other tool' if key not in ours else 'Atropos'}")
            continue
        a, b = ours[key], theirs[key]
        if a["times"] != b["times"]:
            diff.append(f"{key}: run times differ: only here {sorted(a['times'] - b['times'])}, only there {sorted(b['times'] - a['times'])}")
        if str(a["count"]) != str(b["count"]):
            diff.append(f"{key}: run count {a['count']} here, {b['count']} there")
    n = sum(len(v["times"]) for v in ours.values())
    return report("Prefetch", "PECmd", path, f"{len(ours)} files, {n} run times", f"{len(theirs)} files, {sum(len(v['times']) for v in theirs.values())} run times",
                  diff, [f"{failed} files the other tool could not parse are left out"] if failed else [])


SRUM = {
    "D10CA2FE-6FCF-4F6D-848E-B2E99266FA89": ("AppResourceUseInfo", "Timestamp", {
        "foreground_bytes_read": "ForegroundBytesRead", "foreground_bytes_written": "ForegroundBytesWritten",
        "background_bytes_read": "BackgroundBytesRead", "background_bytes_written": "BackgroundBytesWritten",
        "foreground_cycle_time": "ForegroundCycleTime", "background_cycle_time": "BackgroundCycleTime", "face_time": "FaceTime"}),
    "5C8CF1C7-7257-4F13-B223-970EF5939312": ("AppTimelineProvider", "EndTime", {"duration_ms": "DurationMs"}),
    "973F5D5C-1D90-4944-BE8E-24B94231A174": ("NetworkUsages", "Timestamp", {
        "bytes_received": "BytesReceived", "bytes_sent": "BytesSent", "interface_luid": "InterfaceLuid", "l2_profile_id": "L2ProfileId"}),
    "DD6636C4-8929-4683-974E-22C046A43763": ("NetworkConnections", "ConnectStartTime", {
        "connected_seconds": "ConnectedTime", "interface_luid": "InterfaceLuid", "l2_profile_id": "L2ProfileId"}),
    "7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F": ("vfuprov", "EndTime", {"flags": "Flags"}),
    "D10CA2FE-6FCF-4F6D-848E-B2E99266FA86": ("PushNotifications", "Timestamp", {
        "payload_bytes": "PayloadSize", "notification_type": "NotificationType", "network_type": "NetworkType"}),
    # One CSV holds both energy tables; IsLt says which.
    "FEE4E14F-02A9-4550-B5CE-5FA2DA202E37": ("EnergyUsage", "Timestamp", {"chargeLevel": "ChargeLevel", "cycleCount": "CycleCount"}, "False"),
    "FEE4E14F-02A9-4550-B5CE-5FA2DA202E37LT": ("EnergyUsage", "Timestamp", {
        "designedCapacity": "DesignedCapacity", "fullChargedCapacity": "FullChargedCapacity", "cycleCount": "CycleCount",
        "activeAcTime": "ActiveAcTime", "activeDcTime": "ActiveDcTime", "activeEnergy": "ActiveEnergy", "csEnergy": "CsEnergy"}, "True"),
}


def srum(export, folder, evid):
    ours = defaultdict(dict)
    for e in load(export, "srum", evid):
        m = re.match(r"table \{([0-9A-Fa-f-]+)\}(LT)?, AutoIncId (\d+)", e["record_ref"])
        if m:
            ours[m.group(1).upper() + (m.group(2) or "")][int(m.group(3))] = e
    bad = 0
    for guid, spec in SRUM.items():
        name, timecol, figures = spec[:3]
        is_lt = spec[3] if len(spec) > 3 else None
        files = sorted(glob.glob(os.path.join(folder, f"*SrumECmd_{name}_Output.csv")))
        if not files:
            print(f"## SRUM {name}: no CSV in {folder}\n")
            bad += 1
            continue
        theirs = {int(r["Id"]): r for r in rows(files[-1]) if is_lt is None or r.get("IsLt") == is_lt}
        mine = ours.get(guid, {})
        diff, compared = [], 0
        for rid in sorted(set(mine) | set(theirs)):
            if rid not in mine or rid not in theirs:
                diff.append(f"row {rid}: only in {'the other tool' if rid not in mine else 'Atropos'}")
                continue
            e, r = mine[rid], theirs[rid]
            f = e["fields"]
            if not same(e["ts_utc_ns"], t_ns(r[timecol])):
                diff.append(f"row {rid}: time {e['datetime_utc']} here, {r[timecol]} there")
            # An identifier with no name is "(SRUM id N)" here and empty there.
            if "application" in f and re.sub(r"^\(SRUM id \d+\)$", "", f.get("application") or "") != (r.get("ExeInfo") or ""):
                diff.append(f"row {rid}: application {f.get('application')!r} here, {r.get('ExeInfo')!r} there")
            if "user" in f and r.get("Sid") and f.get("user") != r["Sid"]:
                diff.append(f"row {rid}: user {f.get('user')!r} here, {r['Sid']!r} there")
            if "services" in f and f["services"] != (r.get("ExeInfoDescription") or ""):
                diff.append(f"row {rid}: services {f['services']!r} here, {r.get('ExeInfoDescription')!r} there")
            for a, b in figures.items():
                if a in f:
                    compared += 1
                    if str(f[a]) != str(r[b]):
                        diff.append(f"row {rid}: {a} {f[a]} here, {r[b]} there")
        bad += report(f"SRUM {name}", "SrumECmd", files[-1], f"{len(mine)} rows", f"{len(theirs)} rows, {compared} figures compared", diff)
    return bad


def norm_path(p):
    return p.replace("/", "\\").strip("\\").lower()


def mft(export, path, evid):
    """Per file-table entry: the four $STANDARD_INFORMATION times and, where both give them, the four $FILE_NAME times."""
    ours = defaultdict(dict)
    for e in load(export, "mft", evid):
        f = e["fields"]
        kind = "fn" if "$FN" in e["timestamp_desc"] or "file_name" in e["timestamp_desc"].lower() else "si"
        for letter, name in zip("MACB", ("m", "a", "c", "b")):
            if letter in e["macb"]:
                ours[(f["entry"], f["sequence"])][kind + name] = e["ts_utc_ns"]
        ours[(f["entry"], f["sequence"])]["path"] = e["path"]
    cols = {"sib": "Created0x10", "sim": "LastModified0x10", "sic": "LastRecordChange0x10", "sia": "LastAccess0x10",
            "fnb": "Created0x30", "fnm": "LastModified0x30", "fnc": "LastRecordChange0x30", "fna": "LastAccess0x30"}
    theirs = {}
    for r in rows(path):
        theirs.setdefault((int(r["EntryNumber"]), int(r["SequenceNumber"])), r)
    diff, times, missing = [], 0, 0
    for key in sorted(set(ours) | set(theirs)):
        if key not in theirs:
            diff.append(f"entry {key}: only in Atropos ({ours[key].get('path')})")
            continue
        if key not in ours:
            missing += 1
            if missing <= 20:
                r = theirs[key]
                diff.append(f"entry {key}: only in the other tool ({r['ParentPath']}\\{r['FileName']}, in use {r['InUse']})")
            continue
        o, r = ours[key], theirs[key]
        for k, col in cols.items():
            # The tool leaves a $FILE_NAME time empty when it equals the $STANDARD_INFORMATION one.
            their = r[col] or (r[cols["si" + k[2]]] if k.startswith("fn") else "")
            if k not in o or not their:
                continue
            times += 1
            if not same(o[k], t_ns(their)):
                diff.append(f"entry {key}: {col} {o[k]} here, {their} there")
    if missing > 20:
        diff.append(f"... {missing} entries in all are only in the other tool")
    return report("File table", "MFTECmd", path, f"{len(ours)} entries", f"{len(theirs)} entries, {times} times compared", diff)


def shimcache(export, path, evid):
    """By position in the cache: the path, the file's modification time and the executed flag; and the
    entries recovered from the value's slack, by path and time."""
    ours, ours_slack = {}, set()
    for e in load(export, None, evid):
        d = e["timestamp_desc"].lower()
        if "shimcache" not in d:
            continue
        if e["fields"].get("recovered_from_slack"):
            ours_slack.add((e["path"].lower(), e["ts_utc_ns"] // 10**9, bool(e["fields"].get("executed_flag"))))
        else:
            ours[e["fields"]["position"]] = e
    theirs, theirs_slack, untimed = {}, set(), 0
    first_set = None
    for r in rows(path):
        first_set = first_set or r["ControlSet"]
        if r["ControlSet"] != first_set:
            continue
        t = t_ns(r["LastModifiedTimeUTC"])
        if r["FromSlack"].lower() == "true":
            if t[0] is not None:
                theirs_slack.add((r["Path"].lower(), t[0] // 10**9, r["Executed"].lower() == "yes"))
            else:
                untimed += 1
        elif t[0] is None:
            untimed += 1  # an entry with no time is not an event in Atropos
        else:
            theirs[int(r["CacheEntryPosition"])] = r
    diff = []
    executed = 0
    for pos in sorted(set(ours) | set(theirs)):
        if pos not in ours or pos not in theirs:
            diff.append(f"position {pos}: only in {'the other tool' if pos not in ours else 'Atropos'}")
            continue
        e, r = ours[pos], theirs[pos]
        if e["path"] != r["Path"]:
            diff.append(f"position {pos}: path {e['path']!r} here, {r['Path']!r} there")
        if not same(e["ts_utc_ns"], t_ns(r["LastModifiedTimeUTC"])):
            diff.append(f"position {pos}: time {e['datetime_utc']} here, {r['LastModifiedTimeUTC']} there")
        mine, other = bool(e["fields"].get("executed_flag")), r["Executed"].lower() == "yes"
        executed += other
        if mine != other:
            diff.append(f"position {pos}: executed flag {mine} here, {r['Executed']} there")
    for x in sorted(theirs_slack - ours_slack):
        diff.append(f"slack entry {x[0]!r} at {x[1]}: only in the other tool")
    for x in sorted(ours_slack - theirs_slack):
        diff.append(f"slack entry {x[0]!r} at {x[1]}: only in Atropos")
    return report("ShimCache", "AppCompatCacheParser", path, f"{len(ours)} timed entries, {len(ours_slack)} from slack",
                  f"{len(theirs)} timed entries ({executed} flagged executed), {len(theirs_slack)} from slack", diff,
                  [f"{untimed} entries with no time are in the other tool only, by design here"])


def shellbags(export, path, evid):
    """By registry key: the folder's path, the three times of the folder and the key's last write."""
    ours = defaultdict(dict)
    for e in load(export, "shellbags", evid):
        key = e["fields"]["key"].upper().split("BAGMRU", 1)[-1].strip("\\")
        kind = e["timestamp_desc"]
        ours[key][{"shellbag-folder-recorded": "write", "folder-created (shellbag)": "created",
                   "folder-modified (shellbag)": "modified", "folder-accessed (shellbag)": "accessed"}.get(kind, kind)] = e
    theirs = {}
    for r in rows(path):
        key = (r["BagPath"].upper().split("BAGMRU", 1)[-1] + "\\" + r["Slot"]).strip("\\")
        theirs[key] = r
    diff, times, paths, pathdiff = [], 0, 0, 0
    for key in sorted(set(ours) | set(theirs)):
        if key not in ours or key not in theirs:
            diff.append(f"key {key}: only in {'the other tool' if key not in ours else 'Atropos'}")
            continue
        o, r = ours[key], theirs[key]
        for name, col in (("created", "CreatedOn"), ("modified", "ModifiedOn"), ("accessed", "AccessedOn")):
            if name in o and r[col]:
                times += 1
                if not same(o[name]["ts_utc_ns"], t_ns(r[col])):
                    diff.append(f"key {key}: {name} {o[name]['datetime_utc']} here, {r[col]} there")
            elif (name in o) != bool(r[col]):
                diff.append(f"key {key}: {name} time present {'here only' if name in o else 'there only'}")
        # The other tool's FirstInteracted is the folder's own key time. Its
        # LastWriteTime is the time of the key that holds the item, which is
        # the parent's: Atropos dates the folder by its own key.
        if "write" in o and r["FirstInteracted"]:
            times += 1
            if not same(o["write"]["ts_utc_ns"], t_ns(r["FirstInteracted"])):
                diff.append(f"key {key}: own key time {o['write']['datetime_utc']} here, {r['FirstInteracted']} there")
        parent = "\\".join(key.split("\\")[:-1])
        if r["LastWriteTime"] and "write" in ours.get(parent, {}):
            times += 1
            if not same(ours[parent]["write"]["ts_utc_ns"], t_ns(r["LastWriteTime"])):
                diff.append(f"key {key}: parent key time {ours[parent]['write']['datetime_utc']} here, {r['LastWriteTime']} there")
        e = next(iter(o.values()))
        paths += 1
        if e["fields"]["folder"].strip("\\").lower() != r["AbsolutePath"].strip("\\").lower():
            pathdiff += 1
    return report("Shellbags", "SBECmd", path, f"{len(ours)} folders", f"{len(theirs)} folders, {times} times compared", diff,
                  [f"{pathdiff} of {paths} folder paths are worded differently (the two tools name special folders and undecoded items in their own ways)"])


def recycle(export, path, evid):
    ours = {norm_path(e["path"]): e for e in load(export, None, evid) if e["source"] in ("recycle-bin", "recyclebin", "recycle")}
    theirs = {norm_path(r["FileName"]): r for r in rows(path)}
    diff = []
    for p in sorted(set(ours) | set(theirs)):
        if p not in ours or p not in theirs:
            diff.append(f"{p}: only in {'the other tool' if p not in ours else 'Atropos'}")
            continue
        e, r = ours[p], theirs[p]
        if not same(e["ts_utc_ns"], t_ns(r["DeletedOn"])):
            diff.append(f"{p}: deleted {e['datetime_utc']} here, {r['DeletedOn']} there")
        if str(e["fields"].get("size")) != str(r["FileSize"]):
            diff.append(f"{p}: size {e['fields'].get('size')} here, {r['FileSize']} there")
    return report("Recycle Bin", "RBCmd", path, f"{len(ours)} records", f"{len(theirs)} records", diff)


def jumplist(export, path, evid):
    """JLECmd's AutomaticDestinations CSV. By application and entry number: when the entry was last used, its
    target and pin state, and the times, size and volume serial of the shell link stored for it."""
    used, links, app_of = {}, defaultdict(dict), {}
    for e in load(export, None, evid):
        if e["timestamp_desc"] == "jumplist-entry-last-used":
            app_of[e["evidence_id"]] = str(e["fields"]["app_id"]).lower()
            used[(app_of[e["evidence_id"]], int(e["fields"]["entry"]))] = e
        m = re.match(r"jump list stream ([0-9a-f]+)", e["record_ref"])
        if m and e["source"] == "lnk":
            links[(e["evidence_id"], int(m.group(1), 16))][e["timestamp_desc"].split("-")[-1]] = e
    links = {(app_of.get(ev), n): v for (ev, n), v in links.items()}
    diff, compared, untimed = [], 0, 0
    theirs = {}
    for r in rows(path):
        key = (r["AppId"].lower(), int(r["EntryNumber"], 16))  # the tool prints the entry number in hexadecimal
        theirs[key] = r
        last = t_ns(r["LastModified"])
        if key not in used:
            # An entry never used (its time is 1601) is not an event in Atropos.
            if last[0] is not None and last[0] < 0:
                untimed += 1
            else:
                diff.append(f"{key}: only in the other tool")
            continue
        e = used[key]
        compared += 1
        if not same(e["ts_utc_ns"], last):
            diff.append(f"{key}: last used {e['datetime_utc']} here, {r['LastModified']} there")
        # The tool appends "==> name" to a known-folder target.
        if (e["fields"].get("target") or "").lower() != r["Path"].split(" ==> ")[0].lower():
            diff.append(f"{key}: target {e['fields'].get('target')!r} here, {r['Path']!r} there")
        if bool(e["fields"].get("pinned")) != (r["PinStatus"].lower() == "true"):
            diff.append(f"{key}: pinned {e['fields'].get('pinned')} here, {r['PinStatus']} there")
        o = links.get(key, {})
        for kind, col in (("created", "TargetCreated"), ("modified", "TargetModified"), ("accessed", "TargetAccessed")):
            if kind in o and r[col]:
                compared += 1
                if not same(o[kind]["ts_utc_ns"], t_ns(r[col])):
                    diff.append(f"{key}: target {kind} {o[kind]['datetime_utc']} here, {r[col]} there")
            elif kind in o or r[col]:
                diff.append(f"{key}: target {kind} time {'here only' if kind in o else 'there only'}")
        if o and r["FileSize"] and str(next(iter(o.values()))["fields"].get("target_size")) != r["FileSize"]:
            diff.append(f"{key}: target size differs")
    for key in set(used) - set(theirs):
        diff.append(f"{key}: only in Atropos")
    return report("Jump lists", "JLECmd", path, f"{len(used)} entries", f"{len(theirs)} entries, {compared} values compared", diff,
                  [f"{untimed} entries never used (no time) are in the other tool only, by design here"] if untimed else [])


def recmd(export, path, evid):
    """RECmd batch output (any .reb). Every row names a key and its last-write time: those are compared with the
    key times here, to 100 ns. UserAssist rows are compared on program, last run and run count; BAM rows on
    program and time."""
    bs = chr(92)
    # RECmd names the root key ("ROOT", or "S-1-5-21-…_Classes" in UsrClass.dat); Atropos does not.
    def norm(k):
        k = k.upper().strip(bs)
        first = k.split(bs, 1)[0]
        if first == "ROOT" or first.endswith("_CLASSES"):
            k = k[len(first):]
        return k.strip(bs)
    # The two tools word a known folder differently ("%SystemRoot%" + bs + "System32", "{System}"), and an
    # unmapped identifier too: what must agree is the last part of the name.
    tail = lambda p: p.lower().rstrip("}").split(bs)[-1].split(": ")[-1].split(".{")[-1].strip("{}")
    keys, ua, bam, kinds = {}, {}, {}, set()
    for e in load(export, "registry", evid):
        d = e["timestamp_desc"]
        if d.endswith("key-last-write"):
            keys[norm(e["fields"].get("key") or e["path"])] = e["ts_utc_ns"]
            if e["fields"].get("hive"):
                kinds.add(e["fields"]["hive"].upper())
        elif d == "program-last-run (userassist)":
            ua.setdefault((e["ts_utc_ns"] // 10**6, str(e["fields"].get("run_count"))), []).append(e)
        elif d == "program-last-run (bam)":
            bam[(e["fields"].get("sid", "").upper(), e["fields"]["program"].lower())] = e
    have_ua, have_bam = bool(ua), bool(bam)  # rows about another hive in the same CSV are left alone
    diff, n_keys, n_ua, n_bam, unknown, ua_untimed, bam_untimed = [], 0, 0, 0, 0, 0, 0
    seen = set()
    hive = None
    csv_rows = rows(path)
    # Only rows about this hive: several hives share key names (SYSTEM has a Software key too).
    if kinds:
        csv_rows = [r for r in csv_rows if r["HiveType"].upper() in kinds]
    have_ua = have_ua and any(r["Description"] == "UserAssist" for r in csv_rows)
    have_bam = have_bam and any(r["Description"].startswith("Background Activity Moderator") for r in csv_rows)
    for r in csv_rows:
        hive = hive or r["HivePath"]
        k = norm(r["KeyPath"])
        if r["LastWriteTimestamp"] and k not in seen and r["Deleted"].lower() != "true":
            seen.add(k)
            if k not in keys:
                unknown += 1
            else:
                n_keys += 1
                if not same(keys[k], t_ns(r["LastWriteTimestamp"])):
                    diff.append(f"key {k}: time {keys[k]} here, {r['LastWriteTimestamp']} there")
        if r["Description"] == "UserAssist" and have_ua:
            last = t_ns(r["ValueData2"].split(":", 1)[-1])
            count = r["ValueData3"].split(":")[-1].strip()
            if last[0] is None:
                ua_untimed += 1  # never run, or no time recorded: not an event here
                continue
            n_ua += 1
            # Several entries can share a last-run time and count (a shortcut and its program).
            same_time = ua.get((last[0] // 10**6, count), [])
            match = [e for e in same_time if tail(r["ValueData"]) == tail(e["fields"]["program"])
                     or r["ValueData"].lower() == e["fields"].get("program_stored", "").lower()]
            if match:
                same_time.remove(match[0])
            elif same_time:
                diff.append(f"UserAssist: program {same_time[0]['fields']['program']!r} here, {r['ValueData']!r} there")
                same_time.pop(0)
            else:
                diff.append(f"UserAssist {r['ValueData']!r}: last run {r['ValueData2']}, count {count}: not found here")
        if r["Description"].startswith("Background Activity Moderator") and have_bam:
            when = t_ns(r["ValueData2"].split(":", 1)[-1])
            if when[0] is None:
                bam_untimed += 1
                continue
            n_bam += 1
            sid = norm(r["KeyPath"]).split(bs)[-1]
            e = bam.pop((sid, r["ValueName"].lower()), None)
            if e is None:
                diff.append(f"BAM {r['ValueName']!r}: not found here")
            elif not same(e["ts_utc_ns"], when):
                diff.append(f"BAM {r['ValueName']!r}: time {e['datetime_utc']} here, {r['ValueData2']} there")
    if have_ua:
        for left in ua.values():
            for e in left:
                diff.append(f"UserAssist {e['fields']['program']!r}: only in Atropos")
    if n_bam or bam_untimed:
        for e in bam.values():
            diff.append(f"BAM {e['fields']['program']!r}: only in Atropos")
    return report("Registry (RECmd batch)", "RECmd", path, f"{len(keys)} keys",
                  f"{n_keys} key times, {n_ua} UserAssist entries and {n_bam} BAM entries compared", diff,
                  [f"{unknown} keys in the other tool's output are not in this export (another hive, or pass the evidence id)",
                   f"{ua_untimed} UserAssist and {bam_untimed} BAM rows with no time are in the other tool only, by design here"])


KINDS = {"evtx": evtx, "prefetch": prefetch, "srum": srum, "mft": mft, "shimcache": shimcache, "shellbags": shellbags, "recycle": recycle, "jumplist": jumplist, "recmd": recmd}

if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] not in KINDS:
        print(__doc__)
        sys.exit(2)
    evid = int(sys.argv[4]) if len(sys.argv) > 4 else None
    sys.exit(1 if KINDS[sys.argv[1]](sys.argv[2], sys.argv[3], evid) else 0)
