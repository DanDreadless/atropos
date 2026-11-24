"""Dump a $MFT's times with dissect.ntfs, as raw FILETIMEs, for ntfs_dissect.py.

    python mft_dissect_dump.py $MFT > dissect.tsv     (pip install dissect.ntfs)

One line per base file record: entry, sequence, header flags, the four
$STANDARD_INFORMATION times (M A C B) and, for each $FILE_NAME attribute,
its namespace and its four times. Times are read from the attribute's
structure, not through dissect's datetime conversion.
"""
import sys

from dissect.ntfs.mft import Mft

mft = Mft(open(sys.argv[1], "rb"))
bad = 0
w = sys.stdout.write
for rec in mft.segments():
    try:
        h = rec.header
        if h.MultiSectorHeader.Signature != b"FILE":
            continue
        b = h.BaseFileRecordSegment
        if b.SegmentNumberLowPart or b.SegmentNumberHighPart:
            continue  # an extension record; its attributes belong to the base
        attrs = rec.attributes
        si = attrs[0x10][0].attribute.attr if attrs.get(0x10) else None
        row = [str(rec.segment), str(h.SequenceNumber), str(h.Flags)]
        row += [str(getattr(si, k)) for k in ("LastModificationTime", "LastAccessTime", "LastChangeTime", "CreationTime")] if si else ["", "", "", ""]
        for fn in attrs.get(0x30) or []:
            a = fn.attribute.attr
            row += ["fn", str(a.Flags)] + [str(getattr(a, k)) for k in ("LastModificationTime", "LastAccessTime", "LastChangeTime", "CreationTime")]
        w("\t".join(row) + "\n")
    except Exception:
        bad += 1
print(f"records dissect could not read: {bad}", file=sys.stderr)
