"""Fetches the public EVTX-ATTACK-SAMPLES event logs (GPL-3.0) into
testdata/evtx-attack. Run from the repository root; called by
fetch-testdata.sh."""
import json
import os
import urllib.parse
import urllib.request

REPO = "sbousseaden/EVTX-ATTACK-SAMPLES"
os.makedirs(os.path.join("testdata", "evtx-attack"), exist_ok=True)
tree = json.load(urllib.request.urlopen(f"https://api.github.com/repos/{REPO}/git/trees/HEAD?recursive=1"))
for e in tree["tree"]:
    if e["type"] != "blob" or not e["path"].lower().endswith(".evtx"):
        continue
    out = os.path.join("testdata", "evtx-attack", e["path"].replace("/", "__").replace(" ", "_"))
    if os.path.exists(out):
        continue
    url = f"https://raw.githubusercontent.com/{REPO}/master/" + urllib.parse.quote(e["path"])
    with urllib.request.urlopen(url) as r, open(out, "wb") as f:
        f.write(r.read())
