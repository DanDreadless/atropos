"""Amcache: Atropos against regipy's amcache plugin (Martin Korman).

Usage: amcache.py EXPORT.jsonl Amcache.hve [EVIDENCE_ID]
Key: the SHA-1 Amcache holds for each file. Compared: that the two sides
hold the same set of hashes for InventoryApplicationFile, and the time on
each (the key's last write). Key times in general are compared, exactly, by
registry.py.
"""
import sys

from regipy.plugins.amcache.amcache import AmCachePlugin
from regipy.registry import RegistryHive

from common import load, ns, report, same_us

export, path = sys.argv[1], sys.argv[2]
evid = int(sys.argv[3]) if len(sys.argv) > 3 else None

ours = {}
nohash = 0
for e in load(export, "registry", evid):
    if e["timestamp_desc"] not in ("amcache-file-recorded", "amcache-file-hash-recorded"):
        continue
    sha = e["fields"].get("sha1_first_31mb")
    if not sha:
        nohash += 1
        continue
    ours.setdefault(sha.lower(), set()).add(e["ts_utc_ns"])

plug = AmCachePlugin(RegistryHive(path), as_json=False)
plug.run()
theirs = {}
other = 0
for x in plug.entries:
    sha = x.get("sha1")
    if not sha or "file_id" not in x:
        other += 1
        continue
    theirs.setdefault(sha.lower(), set()).add(ns(x["timestamp"]))

diff = []
for sha in sorted(set(ours) | set(theirs)):
    if sha not in ours:
        diff.append(f"{sha}: missing from Atropos")
    elif sha not in theirs:
        diff.append(f"{sha}: only in Atropos")
    elif not all(any(same_us(a, b) for b in theirs[sha]) for a in ours[sha]):
        diff.append(f"{sha}: time {sorted(ours[sha])} here, {sorted(theirs[sha])} there")
sys.exit(1 if report("Amcache files", "regipy amcache plugin", path, f"{len(ours)} distinct hashes", f"{len(theirs)} distinct hashes", diff,
                     [f"{nohash} file entries here carry no hash; {other} entries there are not files with a hash"]) else 0)
