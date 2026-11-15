"""Volume shadow copies: the MD5 of each copy's whole volume, as libvshadow
(Joachim Metz) reads it. Compare with Atropos's own reading, which
TestReadThroughShadowCopies in internal/imagefs checks for the public sample.

    pip install libvshadow-python
    python vss.py VOLUME            # e.g. testdata/vss/vss.raw

For a volume inside a disk image, extract the partition first, or pass the
partition's byte offset as a second argument.
"""
import hashlib
import sys

import pyvshadow


class Offset:
    """The volume, starting part-way into a file."""

    def __init__(self, f, off):
        self.f, self.off, self.pos = f, off, 0

    def seek(self, pos, whence=0):
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        else:
            self.f.seek(0, 2)
            self.pos = self.f.tell() - self.off + pos
        return self.pos

    def tell(self):
        return self.pos

    def read(self, n=-1):
        self.f.seek(self.off + self.pos)
        b = self.f.read(n)
        self.pos += len(b)
        return b

    def get_size(self):
        self.f.seek(0, 2)
        return self.f.tell() - self.off


path = sys.argv[1]
off = int(sys.argv[2]) if len(sys.argv) > 2 else 0
f = open(path, "rb")
vol = pyvshadow.volume()
vol.open_file_object(Offset(f, off) if off else f)
for i in range(vol.number_of_stores):
    s = vol.get_store(i)
    m = hashlib.md5()
    s.seek(0)
    left = s.volume_size
    while left:
        b = s.read(min(left, 1 << 20))
        if not b:
            break
        m.update(b)
        left -= len(b)
    print(f"copy {i + 1}: {s.identifier}  created {s.creation_time}  size {s.volume_size}  md5 {m.hexdigest()}")
