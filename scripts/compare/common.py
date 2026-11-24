"""Shared helpers for the comparison scripts.

Each script reads an Atropos JSON-lines export and the same input file through
an independent parser, and compares record by record on an identifying key and
the times. Nothing here writes into the repository: results go to stdout.
"""
import datetime
import hashlib
import json
import os
import sys

# Names in evidence are not always printable in the console's code page.
sys.stdout.reconfigure(errors="replace")

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def iload(path, source=None, evidence_id=None):
    """Atropos events from a JSON-lines export one at a time, optionally of one source or
    evidence item: for exports too large to hold in memory."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if source and e["source"] != source:
                continue
            if evidence_id and e["evidence_id"] != evidence_id:
                continue
            yield e


def load(path, source=None, evidence_id=None):
    """Atropos events from a JSON-lines export, optionally of one source or evidence item."""
    return list(iload(path, source, evidence_id))


def ns(dt):
    """A datetime as nanoseconds since the Unix epoch, without float rounding."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    d = dt - EPOCH
    return (d.days * 86400 + d.seconds) * 10**9 + d.microseconds * 1000


def same_us(a_ns, b_ns, slack_us=1):
    """Equal to within slack_us microseconds. The other libraries hold
    microseconds at best, and some round where others cut."""
    return abs(a_ns - b_ns) <= slack_us * 1000


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def report(title, tool, path, ours, theirs, differences, notes=()):
    print(f"## {title}")
    print(f"compared with: {tool}")
    print(f"input sha256:  {sha256(path)}")
    print(f"atropos:       {ours}")
    print(f"other:         {theirs}")
    for n in notes:
        print(f"note:          {n}")
    print(f"differences:   {len(differences)}")
    limit = None if os.environ.get("COMPARE_ALL") else 40
    for d in differences[:limit]:
        print(f"  - {d}")
    if limit and len(differences) > limit:
        print(f"  ... and {len(differences) - limit} more (set COMPARE_ALL=1 to list them all)")
    print()
    return len(differences)
