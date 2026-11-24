#!/usr/bin/env bash
# Browser check of the web interface: builds Atropos, serves a fresh empty
# case on a spare port and drives the page the way an examiner would
# (upload, search, zoom, tag, re-parse, drop, verify), failing on any console
# error or content-security-policy violation. Screenshots are left in OUT.
#
#   bash scripts/uicheck/run.sh            needs Node, Edge or Chrome, and testdata/
#   BROWSER=/path/to/chrome OUT=./shots PORT=8499 bash scripts/uicheck/run.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PORT="${PORT:-8497}"
[ -d "$ROOT/testdata/prefetch" ] || { echo "no sample artefacts: run scripts/fetch-testdata.sh first"; exit 1; }
if [ -z "${BROWSER:-}" ]; then
  for b in "/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" "/c/Program Files/Google/Chrome/Application/chrome.exe" \
           "$(command -v google-chrome || true)" "$(command -v chromium || true)" "$(command -v microsoft-edge || true)" \
           "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    [ -n "$b" ] && [ -x "$b" ] && { BROWSER="$b"; break; }
  done
fi
[ -n "${BROWSER:-}" ] || { echo "no browser found: set BROWSER to an Edge or Chrome executable"; exit 1; }
[ -d "$HERE/node_modules/puppeteer-core" ] || (cd "$HERE" && npm install --no-audit --no-fund >/dev/null) || exit 1

WORK="$(mktemp -d)"
OUT="${OUT:-$WORK/shots}"; mkdir -p "$OUT"
BIN="$WORK/atropos$(go env GOEXE)"
(cd "$ROOT" && go build -o "$BIN" .) || exit 1
"$BIN" serve --case "$WORK/case" --examiner uicheck --listen "127.0.0.1:$PORT" </dev/null >"$WORK/serve.log" 2>&1 &
SERVER=$!
# A second, seeded case: artefacts that contradict each other, for the Analysis tab.
(cd "$ROOT" && go run ./scripts/uicheck/seedcase "$WORK/case2") || exit 1
"$BIN" serve --case "$WORK/case2" --examiner uicheck --listen "127.0.0.1:$((PORT+1))" </dev/null >"$WORK/serve2.log" 2>&1 &
SERVER2=$!
trap 'kill $SERVER $SERVER2 2>/dev/null; wait $SERVER $SERVER2 2>/dev/null; chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK/case" "$WORK/case2" "$BIN"' EXIT
for i in $(seq 1 50); do grep -q 'token=' "$WORK/serve2.log" 2>/dev/null && break; sleep 0.2; done
TOKEN2="$(grep -o 'token=[0-9a-f]*' "$WORK/serve2.log" | head -1 | cut -d= -f2)"
[ -n "$TOKEN2" ] || { echo "the second server did not start:"; cat "$WORK/serve2.log"; exit 1; }
for i in $(seq 1 50); do grep -q 'token=' "$WORK/serve.log" 2>/dev/null && break; sleep 0.2; done
TOKEN="$(grep -o 'token=[0-9a-f]*' "$WORK/serve.log" | head -1 | cut -d= -f2)"
[ -n "$TOKEN" ] || { echo "the server did not start:"; cat "$WORK/serve.log"; exit 1; }

native() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }
(cd "$ROOT" && go run ./scripts/uicheck/mkiso "$OUT/disc.iso") || exit 1
(cd "$ROOT" && go run ./scripts/mkrdp -out "$OUT/rdp" >/dev/null) || exit 1
cd "$HERE" && ATROPOS_URL="http://127.0.0.1:$PORT/" ATROPOS_TOKEN="$TOKEN" ATROPOS_URL2="http://127.0.0.1:$((PORT+1))/" ATROPOS_TOKEN2="$TOKEN2" BROWSER="$(native "$BROWSER")" TESTDATA="$(native "$ROOT/testdata")" OUT="$(native "$OUT")" node drive.js </dev/null
rc=$?
echo "screenshots: $OUT"
exit $rc
