"""Virtual disks: the MD5 of the disk inside each image, as libvhdi and
libvmdk (Joachim Metz) read it. Compare with Atropos's own reading
(`VDISK_PRINT=1 go test ./internal/imagefs -run TestVirtualDisks -v`).

    pip install libvhdi-python libvmdk-python
    python vdisk.py FOLDER          # e.g. testdata/vdisk

A differencing image is opened with its parent, found in the same folder by
the identifier the two share.
"""
import glob
import hashlib
import os
import sys

import pyvhdi
import pyvmdk

folder = os.path.abspath(sys.argv[1])
vhds = {}
for p in glob.glob(os.path.join(folder, "*.vhd*")):
    h = pyvhdi.file()
    h.open(p)
    vhds[p] = h


def parent_of(h):
    want = getattr(h, "parent_identifier", None)
    for p, o in vhds.items():
        if want and o.identifier == want:
            return o
    return None


def md5(h):
    m = hashlib.md5()
    h.seek(0)
    left = h.get_media_size()
    while left:
        b = h.read(min(left, 1 << 20))
        if not b:
            break
        m.update(b)
        left -= len(b)
    return m.hexdigest()


for p, h in sorted(vhds.items()):
    if getattr(h, "parent_identifier", None):
        par = parent_of(h)
        if par is None:
            print(os.path.basename(p), "parent not found")
            continue
        h.set_parent(par)
    print(os.path.basename(p), h.get_media_size(), md5(h))
for p in sorted(glob.glob(os.path.join(folder, "*.vmdk"))):
    h = pyvmdk.handle()
    h.open(p)
    h.open_extent_data_files()
    print(os.path.basename(p), h.get_media_size(), md5(h))
