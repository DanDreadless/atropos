#!/usr/bin/env bash
# Fetches public sample artefacts with known answers into testdata/ (gitignored).
# Samples come from the dependency module cache and three public repositories;
# check each source's licence before committing any of them.
#
#   testdata/prefetch/<os>/*.pf     EricZimmerman/Prefetch test files (incl. Bad/)
#   testdata/prefetch-golden/       Velocidex/go-prefetch expected output for four of them
#   testdata/ewf/, testdata/vss/    log2timeline/dfvfs test images
#   testdata/hivelog/               dirty hives and their logs from msuhanov/yarp and mkorman90/regipy
#   testdata/evtx-attack/           sbousseaden/EVTX-ATTACK-SAMPLES
set -euo pipefail
cd "$(dirname "$0")/.."
go mod download
M="$(go env GOMODCACHE)/www.velocidex.com/golang"
mkdir -p testdata/shimcache testdata/prefetch testdata/prefetch-golden
cp "$M"/evtx@v0.2.0/testdata/Security.evtx testdata/
cp "$M"/regparser@*/testdata/NTUSER.DAT testdata/
cp "$M"/regparser@*/appcompatcache/test_data/*.bin testdata/shimcache/
cp "$M"/go-ntfs@v0.2.1/parser/test_data/test.ntfs.dd testdata/
cp "$M"/go-ese@v0.2.0/testdata/SRUM/SRUDB.dat testdata/
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
git clone -q --depth 1 https://github.com/Velocidex/go-prefetch "$T/go-prefetch"
cp "$T"/go-prefetch/fixtures/*.golden testdata/prefetch-golden/
git clone -q --depth 1 https://github.com/EricZimmerman/Prefetch "$T/ez"
cp -r "$T"/ez/Prefetch.Test/TestFiles/. testdata/prefetch/
# E01 images made by ewfacquire (one whole, one split in two) and a volume
# with two shadow copies, from the dfVFS project's test data (Apache-2.0).
mkdir -p testdata/ewf testdata/vss
D=https://raw.githubusercontent.com/log2timeline/dfvfs/main/test_data
for f in ext2.E01 ext2.split.E01 ext2.split.E02; do curl -fsSL -o "testdata/ewf/$f" "$D/$f"; done
curl -fsSL -o testdata/vss/vss.raw "$D/vss.raw"
# Registry hives left dirty, with their transaction logs: yarp's test hives
# (GPL-3.0; among them two hives as Windows itself recovered them) and real
# Windows 10 hives from regipy's tests (MIT, xz-compressed).
Y=https://raw.githubusercontent.com/msuhanov/yarp/master/hives_for_tests
for f in NewDirtyHive1/NewDirtyHive NewDirtyHive1/NewDirtyHive.LOG1 NewDirtyHive1/NewDirtyHive.LOG2 NewDirtyHive1/RecoveredHive_Windows10 \
         OldDirtyHive/OldDirtyHive OldDirtyHive/OldDirtyHive.LOG1 OldDirtyHive/RecoveredHive_Windows7 \
         BadLogHive3/BadLogHive BadLogHive3/BadLogHive.LOG1 BadLogHive3/BadLogHive.LOG2 TruncatedDirtyHive          deleted/DeletedDataHive deleted/DeletedTreeHive deleted/DeletedTreeNoRootFlagHive deleted/DeletedTreePartialPathHive deleted/RemnantsHive; do
  mkdir -p "testdata/hivelog/yarp/$(dirname "$f")"; curl -fsSL -o "testdata/hivelog/yarp/$f" "$Y/${f#deleted/}"
done
R=https://raw.githubusercontent.com/mkorman90/regipy/master/regipy_tests/data
mkdir -p testdata/hivelog/regipy
for f in SYSTEM_B SYSTEM_B.LOG1 SYSTEM_B.LOG2 UsrClass.dat UsrClass.dat.LOG1 UsrClass.dat.LOG2 \
         transactions_NTUSER.DAT transactions_ntuser.dat.log1 transactions_ntuser.dat.log2; do
  curl -fsSL "$R/$f.xz" | xz -dc > "testdata/hivelog/regipy/$f"
done
# The EVTX-ATTACK-SAMPLES set (GPL-3.0): 278 event logs from many channels,
# most saved from larger logs, which rewrites their record headers.
mkdir -p testdata/vdisk
for f in ntfs-fixed.vhd ntfs-dynamic.vhd ntfs-differential.vhd ntfs-parent.vhd ntfs-fixed.vhdx ntfs-dynamic.vhdx          ntfs-differential.vhdx ntfs-parent.vhdx ext2.vmdk; do
  curl -fsSL -o "testdata/vdisk/$f" "$D/$f"
done
python3 scripts/fetch_evtx_attack.py 2>/dev/null || python scripts/fetch_evtx_attack.py
chmod -R u+w testdata
echo "testdata: $(find testdata -type f | wc -l) files"
