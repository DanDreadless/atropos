"""Reads E01 images with libewf (pyewf) and prints, for each, the number of
segments, the media size, the MD5 of the media as libewf reads it and the MD5
stored in the image. Compare with the ewf.computed_md5 and ewf.stored_md5
facts Atropos records for the first segment.

    pip install libewf-python
    python ewf.py image.E01 [another.E01 ...]
"""
import sys, hashlib, glob, os
import pyewf
for first in sys.argv[1:]:
    try:
        first = os.path.abspath(first); names = pyewf.glob(first)
        h = pyewf.handle(); h.open(names)
        size = h.get_media_size(); m = hashlib.md5(); left = size
        while left:
            b = h.read(min(left, 1 << 20))
            if not b: break
            m.update(b); left -= len(b)
        stored = h.get_hash_value("MD5")
        print(os.path.basename(first), len(names), "segments", size, "bytes", m.hexdigest(), "stored", stored)
        h.close()
    except Exception as e:
        print(os.path.basename(first), "ERROR", e)
