"""Registry: Atropos against dissect.regf (Fox-IT) and regipy (Martin Korman).

Usage: registry.py EXPORT.jsonl HIVE [EVIDENCE_ID]
Key times: every key's path and last-write time, against dissect.regf.
UserAssist: program, run count and last-run time, against regipy's plugin.
"""
import datetime
import sys

from dissect.regf import RegistryHive

from common import load, ns, report, same_us

export, path = sys.argv[1], sys.argv[2]
evid = int(sys.argv[3]) if len(sys.argv) > 3 else None
events = [e for e in load(export, None, evid) if e["source"] in ("registry", "shellbags")]

# Every key has exactly one event whose record_ref names its node, whatever
# type the event was given (autostart, mount point...).
ours = {}
for e in events:
    if e["record_ref"].startswith("key node at offset"):
        p = e["fields"].get("key") or e["path"]
        if e["timestamp_desc"] == "registry-key-last-write":
            p = e["path"]
        ours.setdefault(e["record_ref"], (p, e["ts_utc_ns"], e["timestamp_desc"]))

theirs = {}
hive = RegistryHive(open(path, "rb"))


def walk(key, p):
    # The FILETIME itself: dissect's own conversion goes through a float.
    theirs[p or "\\"] = (key.cell.LastWriteTime - 116444736000000000) * 100
    for sub in key.subkeys():
        walk(sub, p + "\\" + sub.name)


walk(hive.root(), "")

diff = []
by_path = {}
for ref, (p, t, typ) in ours.items():
    by_path.setdefault(p, []).append((t, typ, ref))
for p in sorted(set(by_path) | set(theirs)):
    if p not in by_path:
        diff.append(f"key {p}: missing from Atropos")
    elif p not in theirs:
        diff.append(f"key {p}: only in Atropos ({by_path[p][0][1]})")
    elif not any(t == theirs[p] for t, _, _ in by_path[p]):
        diff.append(f"key {p}: time {by_path[p][0][0]} here, {theirs[p]} there")
bad = report("Registry key last-write times", "dissect.regf", path, f"{len(by_path)} keys", f"{len(theirs)} keys", diff,
             ["times compared exactly, to 100 nanoseconds"])

# UserAssist.
try:
    from regipy.plugins.ntuser.user_assist import GUID_TO_PATH_MAPPINGS, UserAssistPlugin
    from regipy.registry import RegistryHive as RegipyHive

    plug = UserAssistPlugin(RegipyHive(path), as_json=False)
    plug.run()
    theirs_ua = {}
    for x in plug.entries:
        t = x.get("timestamp")
        if isinstance(t, str):
            t = datetime.datetime.fromisoformat(t)
        # regipy names known folders its own way; put the identifier back so
        # both sides are compared as the hive stores them.
        name = x["name"]
        for guid, shown in sorted(GUID_TO_PATH_MAPPINGS.items(), key=lambda kv: -len(kv[1])):
            if name.startswith(shown + chr(92)):
                name = guid + name[len(shown):]
                break
        theirs_ua[name] = (x.get("run_counter"), ns(t) if t else None)
    ours_ua = {}
    untimed = 0
    for e in events:
        if e["timestamp_desc"] == "program-last-run (userassist)":
            f = e["fields"]
            ours_ua[f.get("program_stored") or f["program"]] = (f.get("run_count"), e["ts_utc_ns"])
    diff = []
    for name in sorted(set(ours_ua) | set(theirs_ua)):
        if name not in ours_ua:
            if theirs_ua[name][1] is None or theirs_ua[name][1] < ns(datetime.datetime(1980, 1, 1)):
                untimed += 1  # no time: Atropos keeps these off the timeline
            else:
                diff.append(f"{name}: missing from Atropos")
        elif name not in theirs_ua:
            diff.append(f"{name}: only in Atropos")
        else:
            (c1, t1), (c2, t2) = ours_ua[name], theirs_ua[name]
            if t2 is None or not same_us(t1, t2):
                diff.append(f"{name}: time {t1} here, {t2} there")
            if c1 != c2:
                diff.append(f"{name}: run count {c1} here, {c2} there")
    bad += report("UserAssist", "regipy user_assist plugin", path, f"{len(ours_ua)} timed entries", f"{len(theirs_ua)} entries",
                  diff, [f"{untimed} entries there have no last-run time and are deliberately not events here"])
except ImportError as err:
    print(f"UserAssist not compared: {err}\n")
sys.exit(1 if bad else 0)
