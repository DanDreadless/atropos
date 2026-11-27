# Comparison with other tools

Atropos output compared, record by record, with independent parsers of the same files. The scripts are in `scripts/compare/`; this file records what was run, what differed and why. Nothing here contains evidence: results on the owner's own files are given as counts only.

**First round: 13 November 2026.** Run on Windows 11 with Python 3.14. Rows dated 14 November were added with the Stage 3 parsers.

## What it was compared with

| Tool | Version | Used for |
|---|---|---|
| dissect.regf, dissect.ntfs, dissect.esedb, dissect.eventlog (Fox-IT) | 3.14, 3.16, 3.18, 3.11 | registry keys, the file table, SRUM, event logs; dissect.ntfs 3.16 again on 23 November, on Kali, for every `$FILE_NAME` of the owner's `$MFT` (`mft_dissect_dump.py`) |
| regipy (Martin Korman) | 6.5.0 | UserAssist, Amcache |
| python-evtx (Willi Ballenthin) | 0.8.1 | event logs |
| Hindsight (Ryan Benson) | 20260600 | the meaning of Chromium's history codes |
| Windows itself | `Get-LocalUser`, `Get-MpThreatDetection`, `Get-MpThreat` | SAM accounts, Defender detection records |
| EvtxECmd, PECmd, SrumECmd, MFTECmd, AppCompatCacheParser, SBECmd, RBCmd, JLECmd, RECmd (Eric Zimmerman) | 2026.10 releases, .NET Framework 4 builds, fetched 14 November 2026 with `Get-ZimmermanTools.ps1 -NetVersion 4` | event logs, prefetch, SRUM, the file table, ShimCache, shellbags, the Recycle Bin, jump lists |
| libewf (pyewf, Joachim Metz) | 20260924 | E01 images |
| SIDR (Stroz Friedberg) | main branch, 15 November 2026 (its golden reports) | the Windows Search index |
| libvshadow (pyvshadow, Joachim Metz) | current on 14 November 2026 | volume shadow copy catalog |
| The Sleuth Kit (Brian Carrier) | 4.14.0, Kali Linux's package, run on 23 November 2026 | NTFS, FAT and ext volumes (`fls -m`, `icat`); `mactime` on the bodyfile export |

The first round used independent libraries; the second, on 14 November, used the Zimmerman tools (`scripts/compare/ez.py`). **Not yet compared with: AmcacheParser (not in the .NET 4 set), RegRipper, Plaso or DHParser.** The Sleuth Kit was added on 23 November 2026.

## Inputs

Public samples (`scripts/fetch-testdata.sh`):

| File | SHA-256 |
|---|---|
| `testdata/Security.evtx` | `d04f923e10831c3f75ba051c284b970622bbec5c08884cf934edab43d74f15d7` |
| `testdata/NTUSER.DAT` | `4a3232850f9677de96774b4de0020ac7f5e2efeb5e4576a200bb751d9e1c9d1d` |
| `testdata/test.ntfs.dd` | `2b045901147e049e9a97f2e4afe47f4fa5d46c545e3a1c529a5b31d2835cf53a` |
| `testdata/SRUDB.dat` | `def113048c6c940bbcafad576a28f90444e53a9f8cec498067d128caacf2ac90` |
| `testdata/ewf/ext2.E01` | `ab9ea9a4951b74c37025ba40a978e85b1e4a0d94438080afb636144170d3f35b` |
| `testdata/ewf/ext2.split.E01` | `d14f130c462b0ab8efb6bb44bbfe5680e00ffaa90538cde84579d1eb0dcac00f` |
| `testdata/ewf/ext2.split.E02` | `b508375954ec1d1caeed8a6e5fc503f98493816ad6a3af89f5d220244c5f2864` |
| `testdata/vss/vss.raw` | `e633f0be5fb9ee9a07d44ba5223b786012ce89e9f0024f93d743568e6d052f16` |
| `testdata/ext/ext2.raw` | `a6c2f0e39afe6c6ab432ca5465349fcefe8dc944398e97b2d957d3f89dbb5d80` |
| `testdata/ext/ext4.raw` | `d88dd5f6774526a94ad74e061c6a4245fef302e03c917277fb4043e30ed8b434` |
| `testdata/fat/fat12.raw` | `60aacdf576dad24743d80a66a045bcdfbbd0ef4d368cece060bf087ee114da2f` |

The owner's own files, from a Windows 11 machine, read from copies and reported as counts: `NTUSER.DAT`, `UsrClass.dat`, `SAM`, `SECURITY`, `Amcache.hve`, `SRUDB.dat`, seven Defender detection records and one MPLog; and on 23 November the system volume's `$MFT` (1.37 GB, 1,335,808 records), `$LogFile` (64 MB) and `$J` (38 MB), exported with FTK Imager.

## Results

| Parser | Compared with | Input | Compared | Result after fixes |
|---|---|---|---|---|
| `evtx` | dissect.eventlog | public Security.evtx | record number, time, event ID, provider, channel, computer of 739 records | no differences |
| `evtx` | the record headers, read directly | the same | time of 739 records, to 100 ns | no differences |
| `evtx` | python-evtx | the same | time and event ID | no differences in the 389 records it returns |
| `registry` key times | dissect.regf | public NTUSER.DAT | path and last-write time of 1,127 keys, to 100 ns | no differences |
| `registry` key times | dissect.regf | owner's five hives | 12,685 + 13,735 + 79 + 115 + 20,104 keys, to 100 ns | no differences |
| UserAssist | regipy | public NTUSER.DAT; owner's NTUSER.DAT | program, run count, last run of 13 and 222 entries | no differences |
| Amcache | regipy | owner's Amcache.hve | the set of 12,066 file hashes and the time on each | no differences |
| `ntfs-mft` | dissect.ntfs | public test.ntfs.dd | 132 `$STANDARD_INFORMATION` times of 33 records to 100 ns; path, directory flag, stream names | no differences |
| `srum` | dissect.esedb | public SRUDB.dat | 6,088 rows: time, application, account, 11,949 figures | no differences |
| `srum` | dissect.esedb | owner's SRUDB.dat | 70,164 rows: time, application, account, 244,114 figures | no differences |
| SAM accounts | `Get-LocalUser` | owner's SAM | name, RID, disabled, last logon, password set, for 5 accounts | no differences |
| Defender detection records | `Get-MpThreatDetection`, `Get-MpThreat` | owner's 7 records | ids, severity, category, status, source, execution status, process, 3 times | no differences |
| Chromium codes | Hindsight's tables | none (source against source) | visit source, page transition and its qualifiers, download state, danger type, interrupt reason | meanings agree on every shared code |
| E01 reader | libewf, and the hash ewfacquire stored | public `ext2.E01`, and `ext2.split.E01` with `.E02` | MD5 of the 4,194,304 bytes of media | no differences (14 November) |
| E01 reader | libewf, the hash EnCase 7.2.1.1 stored, and dissect.ntfs over libewf | public `2011-10-19-Sample.E01` (SHA-256 `fc38dd500b41cb397e8a09add383610bb7934fdadda289d82c9a838fed85e99d`) | MD5 of 157,285,888 bytes of media; the names in the volume's root | no differences |
| Chromium cookies | the table itself, counted with SQL | owner's `Cookies` | 4,560 events against 1,941 rows' distinct times | no differences |
| `evtx` | EvtxECmd (`evtx_set.py`) | the 278 logs of the public EVTX-ATTACK-SAMPLES set (277 distinct; Security, System, Sysmon, PowerShell, BITS, RDP, ETW captures and more) | 37,357 records: record number, time to 100 ns, event ID, provider, channel, computer | no differences, apart from the channel of 29,524 records in two ETW captures, stored as a number, which EvtxECmd leaves empty (15 November) |
| `evtx` | EvtxECmd | public Security.evtx | record number, time to 100 ns, event ID, provider, channel, computer of 739 records | no differences |
| `prefetch` | PECmd | 54 public prefetch files (XP to Windows 10) | every run time (98) and the run count of each file | no differences |
| `srum` | SrumECmd | public SRUDB.dat | 6,088 rows of four tables: time, application, account, 17,555 figures | no differences |
| `srum`, the other tables | SrumECmd | public SRUDB.dat | vfuprov (44 rows, end time and flags), push notifications (10 rows, 30 figures), energy use and its long-term table (1 row, 7 figures) | no differences (15 November) |
| `ntfs-mft` | MFTECmd | `$MFT` of the public sample volume and of the public EnCase image | 224 `$STANDARD_INFORMATION` times of 56 entries, to 100 ns | no differences |
| ShimCache | AppCompatCacheParser | owner's SYSTEM hive | path, time and executed flag of 895 timed entries by position (424 flagged); 20 entries recovered from slack, by path, time and flag | no differences (15 November) |
| Shellbags | SBECmd | owner's NTUSER.DAT and UsrClass.dat | 774 folders by key: created, modified and accessed times, the folder's own key time and its parent's (3,157 times) | 4 modified times not decoded here (see below) |
| `recycle-bin` | RBCmd | owner's 3 `$I` records | path, size, deletion time | no differences |
| `lnk` (loose shortcut files) | LECmd 2026.10 (26 November 2026, `ez.py lnk`) | six shortcuts made with `WScript.Shell` (file, folder, programs with arguments, a share, a missing target) and the owner's 92 shared Start Menu shortcuts | per file: three target times (LECmd writes seconds), size, target path, arguments, working directory, relative path, volume serial and label, description, tracker machine and MAC; the target's file-table entry and sequence, the four tracking identifiers and the time in the file identifier; 70 with times, 1,400 values | no differences after item 18; the 28 with no times compared by a throwaway test on target, arguments and working directory: all agree |
| `jump-list` and the shell links inside | JLECmd | owner's 2 jump lists with entries | 100 entries: last used, target, pin state; 195 target times, 65 sizes | no differences |
| Registry transaction logs | Windows' own recovery (yarp's test hives) | NewDirtyHive1 (new format, Windows 10), OldDirtyHive (old format, Windows 7) | every byte of the hive bins | identical, apart from what Windows writes when saving (see the handoff) |
| Registry transaction logs | RECmd, `--nl false`, with `AllKeys.reb` (whole branches) and `DFIRBatch.reb` | regipy's real Windows 10 SYSTEM_B, UsrClass.dat, NTUSER.DAT, each with LOG1 and LOG2 | logs and entries applied; 25,684 key times; 14 UserAssist entries | no differences. Without the logs: 3,020 keys missing, 274 times stale |
| Deleted registry keys | yarp's test expectations | DeletedDataHive, DeletedTreeHive, DeletedTreeNoRootFlagHive, DeletedTreePartialPathHive, RemnantsHive | keys, paths, values | identical |
| Deleted registry keys | RECmd `--recover` (default), `Root.reb` from the root | regipy's real UsrClass.dat with its logs applied | path and last-write time of each deleted key | RECmd's 9 all found, the same; Atropos also reports 27 whose parent is gone, which RECmd omits |
| Registry key times, UserAssist, BAM | RECmd with its `DFIRBatch.reb` | owner's SYSTEM and NTUSER.DAT | last-write time of the 930 keys the batch reports, to 100 ns; 222 UserAssist entries (program, last run, run count); 77 BAM entries (program, account, time) | no differences |
| Whole timeline over the public artefacts | Plaso 20261027 (`log2timeline --single_process`, `psort -o json_line`; in a venv on the Kali VM, 27 November 2026; `plaso.py`) | the public samples in `testdata/` that are files rather than images: `Security.evtx`, the 278 EVTX-ATTACK-SAMPLES logs, `NTUSER.DAT`, regipy's and yarp's hives with their logs, ShimCache values, prefetch, `SRUDB.dat`, Windows Search (396 files) | every time of each file, to the microsecond (one either way: Plaso rounds, Atropos is cut), whatever each tool calls it; Plaso's file-system times of the copies left out | 175,388 Plaso events; 131,226 have a time Atropos has for that file. Of the rest: about 41,000 are in `.xz` copies of the hives, which Plaso decompresses and Atropos does not read; 957 are event records' header times, which Atropos keeps in the record's fields rather than as a second event; 162 key times and 8 BAM times are earlier in Plaso, which does not apply transaction logs (Atropos has each key and entry, later); 205 are old event records Plaso recovers from logs' unused space (Atropos recovers those too since item 21); 62 prefetch volume creation times and 33 ProgramsCache shell-item times are not read here. Atropos has about 13,000 times Plaso does not: Windows Search, SRUM activity ends and the `vfuprov` table, deleted keys. The run found two defects in Atropos, items 19 and 20 |
| Recent-file and dialog lists | RECmd with its `DFIRBatch.reb` (26 November 2026) | owner's NTUSER.DAT | Office File and Place MRU (path and last-opened time per item); OpenSavePidlMRU per extension and LastVisitedPidlMRU (entries in MRU order, the newest's time); TypedURLs and TypedPaths; MountPoints2 (each volume or share key and its last-write time): 24 Office entries, 23 extension lists, 19 LastVisited entries, 3 typed, 128 list entries, 18 mount points | no differences after the two fixes in item 17; RECmd names the profile folder `{59031a47-3f72-44a7-89c5-5595fe6b30ee}` "Shared Documents Folder (Users Files)", Atropos "User folder" (its entries are the profile's `.ssh`, `Code`), compared as the same |
| VHD, VHDX, VMDK readers | libvhdi (pyvhdi 20260901), libvmdk (pyvmdk 20260714), `scripts/compare/vdisk.py` | dfVFS's ntfs-fixed, -dynamic, -differential and -parent as VHD and VHDX, and ext2.vmdk | MD5 of each disk's contents | identical (the VMDK's is also the stored MD5 of ext2.E01, the same disk) |
| E01 test writer | libewf | five images written by `imagetest.E01`: stored and compressed chunks, one to three segments, with and without a set identifier or a table base | libewf opens each and reads the same media | no differences |
| FAT reader | dfVFS's own test expectations | dfVFS's `fat12.raw`, and `fat-differential.vhd`/`.vhdx` with their parents | names, sizes and contents of the 4 entries; the directory entry offset dfVFS uses as the inode number (0x62A0) | identical |
| ext reader | dfVFS's own test expectations | dfVFS's `ext2.raw` and `ext4.raw` | inode numbers of the 5 names, mode, owner, group, size and link count of one file, the symbolic link's target, content; creation time present only on ext4 | identical |
| FAT reader | The Sleuth Kit `fls -m -z UTC` (`fls.py`) | dfVFS's `fat12.raw` | path, deleted flag, size, modified, accessed and created times of 4 entries | no differences (23 November) |
| ext reader | The Sleuth Kit `fls -m` (`fls.py`) | dfVFS's `ext2.raw` and `ext4.raw` | path, deleted flag, size, link target, modified, accessed, changed and created times of 6 entries each | no differences (23 November) |
| `ntfs-mft` | The Sleuth Kit `fls -m` (`fls_ntfs.py`) | public `test.ntfs.dd`; the volume in the public `2011-10-19-Sample.E01` (its `$MFT` taken out with `icat`) | by MFT entry: path, deleted flag, the four `$STANDARD_INFORMATION` times and the four `$FILE_NAME` times, to the second; 32 and 22 entries, 128 and 88 `$FILE_NAME` times | no differences (23 November). Every `$FILE_NAME` time on both volumes equals one of the entry's `$SI` times, so Atropos showed no separate `$FN` event: that path is still unproven |
| `ntfs-mft` | MFTECmd (`ez.py mft`, every name row) and dissect.ntfs | owner's `$MFT` | 1,268,224 entries; 5,935,962 times, `$SI` and the `$FN` of every name, to 100 ns | `$SI`: no differences. `$FN`: none after two fixes (below, 15 and 16), apart from 339 that are MFTECmd's (below), each confirmed in dissect's reading (23 November) |
| `usn-journal` | MFTECmd | owner's `$J` | number of records | 321,401 on both sides. The last 484 KB of the exported file are not records (below); Atropos warns of them, MFTECmd passes over them |
| E01 reader and file extraction | The Sleuth Kit `icat`, over media written out by libewf | public `2011-10-19-Sample.E01` | the `$MFT` Atropos extracts from the image against `icat VOLUME 0` | identical, SHA-256 `042c6032…aab2c8`; libewf's media MD5 equals the stored one (23 November) |
| Bodyfile export | The Sleuth Kit `mactime -b -d -z UTC` | export of a case holding the FAT, ext and NTFS samples | `mactime` reads all 109 lines without a warning; 127 rows out | read cleanly (23 November). Rows dated `Xxx Xxx 00 0000` are times the file system does not keep (FAT has no change time, ext2 no creation time), which `fls`'s own body files leave at 0 the same way |
| Windows Search | SIDR (Stroz Friedberg), its own reports on its public samples | `Windows.db` (Windows 11) and `Windows.edb` (Windows 10) | every property SIDR reports for every item: paths, file times, gather times, web addresses, activity start and end, application, content address | identical: 21,659 values of 839 items, and 8,783 values of 1,182 items. Local-clock activity times are labelled local where SIDR writes them as UTC; 119 of 170 indexed summaries in the ESE sample are not returned by go-ese |
| Shadow copy list | libvshadow | public `vss.raw` | identifier, creation time and volume size of 2 copies | no differences |
| Reading through shadow copies | dfVFS's own test, and the sample's design | public `vss.raw` | the 16 bytes at 0x1C9 and 8 near the end of copy 2; which files each copy holds (`vss1` and `vss2` were written after copies 1 and 2); unchanged files byte for byte | as expected. Not yet compared with libvshadow: `scripts/compare/vss.py` prints the MD5 of each copy for comparison with `TestReadThroughShadowCopies` |
| WMI subscriptions | `Get-CimInstance` in `root\subscription` | owner's repository | number of filters, consumers and bindings (1, 1, 1) and their names | no differences |
| WMI property names | `Get-CimInstance` in `root\subscription` | owner's repository (15 November 2026, a copy, deleted after) | every value named from the carved class definitions, for the filter, the consumer and the binding (compared for equality, not printed) | 12 named values equal; the binding's two references are the same objects written in CIM's notation (`__EventFilter (Name = ...)`) rather than the stored one; 5 properties CIM shows are class defaults, which the instance does not store and Atropos does not give |
| Browser profile tables | the tables themselves, counted with SQL | owner's Chrome profile | events per kind against rows with a usable, distinct time | no differences |

## What the comparison found in Atropos

Each was fixed, with a test, on the day it was found.

1. **Registry key times were cut to whole seconds.** The registry library's accessor drops the fraction. Every `registry-key-last-write` event, and everything dated by a key (autostart keys, services, shellbag folders, the recent-file lists, SAM name keys), was up to a second early. The time is now read from the key node as a FILETIME. Found on the public hive: 1,127 of 1,127 keys differed.
2. **SRUM record times could be one second early.** SRUM stores a record's time as a count of days in a floating-point number, and the ESE library cuts the result to whole seconds: a time written as 19:55:00 and stored a fraction of a microsecond short came back as 19:54:59. 160 of 6,088 rows in the public sample. The number is now read as stored and rounded to the millisecond.
3. **Registry names in other scripts came out as noise.** A key or value name is stored as Latin-1 or as UTF-16, with a flag saying which; the library returns the bytes as they are. 16 keys in the owner's UsrClass.dat were affected. Names are now decoded by the flag.
4. **Most Amcache file entries were not recognised.** On the owner's Windows 11 build 15,155 of 18,025 entries under `InventoryApplicationFile` hold only a program identifier and a file identifier, with the file's name in the key's own name. They were left as plain key events. They are now `amcache-file-hash-recorded`, with the name and the SHA-1.
5. **UserAssist paths showed known-folder identifiers.** `{1AC14E77-…}\cmd.exe` is now shown as `%SystemRoot%\System32\cmd.exe`, with the stored form kept in `program_stored`. Not an error, but every other tool does it and the anomaly rules match on paths.
6. **Nine Chromium codes had no name:** visit sources 6 and 7, download danger types 18 to 23, interrupt reason 32. The reading of visit source 0 as "synced", on which three quarters of the owner's history depends, agrees with Hindsight.
7. **ShimCache times were cut to whole seconds** (found 14 November, reading AppCompatCacheParser's result beside ours: every one of 895 times ended in `.000000`). The library converts the FILETIME to seconds. The stored value is now read for the Windows 10 and 11 layout; 700 of the owner's 895 entries gained their fraction. Older layouts still give whole seconds.
8. **A delegate folder's modified time was not read.** SBECmd showed a modified time on six shellbag items where Atropos had none: items wrapped by a delegate folder hold an ordinary file entry at a fixed offset. Now read.
9. **SRUM activity records showed the stored identifier**, `!!svchost.exe!2037/07/18:06:45:20!15eca![netsvcs]`, as the application. SrumECmd shows the program's name. Atropos now does too, keeping the stored form, the link time and the services in fields.
10. **Known-folder targets in jump lists** (`knownfolder:{GUID}`) are now named where the GUID is known.
15. **A file's other names had no times** (23 November, the owner's `$MFT` against MFTECmd). A file with several names (hard links, a POSIX name beside a Win32 one, a DOS short name renamed apart from its long name) has a `$FILE_NAME` attribute for each, with its own four times, among them when that name was made. The file-table library reports the first attribute's times only. 38,604 files on the owner's volume had names whose times differ; their times were not on the timeline. Each other name's moments are now `$FN` events naming it (`file_name`, `file_name_namespace`, `file_name_parent_entry`).
16. **Names in extension records were not read from a bare `$MFT`, and 230 files were left out** (23 November, same comparison). When a file's attributes overflow its record and the attribute list is itself held outside the record, a bare `$MFT` cannot follow it. The library then misses those names, and a record with no name of its own it drops altogether: 230 files in use on the owner's volume were absent from the timeline. Atropos now finds every extension record holding a name in one pass, keyed by its base record and sequence number, as MFTECmd does; the 230 are read directly (`names_only_in_extension_records`), without their streams.
17. **Two typed lists were not on the timeline** (26 November, the owner's NTUSER.DAT against RECmd's DFIR batch). Explorer's `TypedPaths` (paths typed into the address bar) was not read; and a `TypedURLs` key with no `TypedURLsTime` beside it, as on the owner's Windows 11, gave no event, its address only in the key's own. Both are now most-recently-used lists, url1 the newest, dated by the key's last write (`path-typed-latest (explorer)`, `url-typed-latest (internet explorer)`), with url10 ordered after url2.
18. **A shortcut with no target times was lost** (26 November, against LECmd). 28 of 98 shortcuts (most of them installers' Start Menu entries, and any made to a target that does not exist) carry no times; Atropos gave a note and nothing else, so their target and arguments were neither searchable nor seen by the command checks. They are now kept as text. And a shortcut with no link information was named by its relative path (`..\..\NoSuchFolder\gone.exe`); it is now named from its item list (`This PC\C:\NoSuchFolder\gone.exe`), as LECmd names it.
19. **A hive offered more than two of its logs got none** (27 November, running Plaso over the public samples, though Plaso does not apply logs: the per-file comparison showed yarp's `NewDirtyHive2` with none of its recent changes). yarp's set holds four logs naming that hive: its own two and `BadLogHive3`'s. Atropos kept the two whose entries start earliest and refused the rest as "a third new-format log", so which hive lost its changes depended on the order the files came in. Now each pair is tried without writing and the pair whose entries reach furthest is applied, ties broken by the logs' bytes (`TestMoreLogsThanWindowsKeeps`, all 24 orders).
20. **A submission stated to be not from a host took a SYSTEM hive's computer name** (27 November, same run, from the event logs' notes naming "the host this log came from"). The name is now a note and the events have no host (`TestAssignedHost`).
21. **Old event records in a log's unused space were not read** (27 November, from the Plaso run). They are now recovered and marked; 7,240 from the public logs, checked against python-evtx where it can decode them (101, all agreeing; the handoff has the detail). Recovering them showed velocidex/evtx allocating without bound on a damaged record, so the library is now a patched copy (`third_party/evtx`).
14. **Logs saved from another log lost most of their records** (15 November). "Save filtered log file as" and `wevtutil epl` rewrite each record's header: the record numbers start again from 1 and the header's time can be zero. Atropos took both from the header, so of the 278 public attack samples only 103 parsed cleanly, 158 were partial and 16 gave no events at all. Each event's own `TimeCreated` and `EventRecordID` are now used, as Event Viewer and EvtxECmd use them; the rewritten values are kept as `record_written` and `record_number_in_file`. The library gives `TimeCreated` only as floating-point seconds, good to about a microsecond, so the exact stored FILETIME is found in the record's bytes. On an ordinary log nothing changes (the Security sample still matches to 100 ns).
13. **ShimCache slack and the executed flag were not read** (15 November). On Windows 10 1703 and later each entry's data carries tagged items, and tag 0x100 marks it executed; and the registry cells holding the value are usually longer than the value, with entries from when the cache was longer in the unused end. Both now read; 424 and 20 on the owner's SYSTEM hive, agreeing with AppCompatCacheParser.
12. **Transaction logs were not applied** (not a comparison finding, but measured by one): a hive copied from a running system lacked whatever was only in its logs. On regipy's real hives that was 3,020 keys.
11. **BAM entries for Store apps were left out.** A program in the BAM key was recognised by a backslash in its name; a Store app is named by its package (`Microsoft.WindowsTerminal_8wekyb3d8bbwe`). RECmd listed 77 entries where Atropos had 41. Every value but `Version` and `SequenceNumber` is now read.

## Differences that are the other tool's

- **dissect.eventlog, dissect.regf and python-evtx convert a FILETIME through a floating-point number**, which at present-day values is good to two or three microseconds. Atropos keeps all 100-nanosecond digits, and the event-log script proves it by reading the record headers itself. The scripts allow three microseconds against those libraries, and compare registry times against dissect's raw FILETIME instead of its converted one.
- **python-evtx returned 389 of the 739 records** in the public log: it reads the number of chunks the file header counts, and this log has more.
- **MFTECmd writes no row for a DOS short name**, so a DOS name whose times differ from its long name's is not in its output: 134 times on the owner's volume, all confirmed by dissect.ntfs.
- **MFTECmd leaves out 205 deleted records** on the owner's volume that dissect.ntfs and Atropos both read (records at the end of the table, sequence 2).
- **The Sleuth Kit 4.14.0 as packaged by Kali crashes on every E01** (23 November 2026): `img_stat`, `mmls` and `fls` end in a segmentation fault on the public `ext2.E01` and `2011-10-19-Sample.E01`, so its libewf support is broken. The media were written out with pyewf (`libewf-python` 20260924) and TSK run on the raw copy.
- **dissect.esedb returned 2 rows of the owner's SRUM database with every column empty.** Atropos does not emit them.

## Deliberate differences

- **UserAssist entries with no last-run time are not events** (1 in the public hive, 124 in the owner's). regipy lists them. An event needs a time; they are not lost, since the key's values are in the key's own event.
- **A channel stored as a number** (in logs converted from ETW captures) is shown as that number; EvtxECmd shows nothing.
- **A directory's size is 0 here** on FAT and ext; `fls` gives the size of its data (2,048, 1,024, 12,288 bytes). A FAT directory entry records no size at all; TSK counts its clusters. `fls.py` does not compare directory sizes.
- **An exported `$J` can end in data that is not records.** FTK Imager's export of the owner's journal ends in 121 pages (484 KB) after the last record that hold no valid record. Atropos warns and marks the run partial; MFTECmd says nothing.
- **The root directory (MFT entry 5) is an event here**; `fls -r` lists what is in the root, not the root itself.
- **Four reserved file-table records (12 to 15) have times and no name.** dissect.ntfs lists them; Atropos does not show a record that is not a file.
- **ShimCache entries with no time are not events** (130 in the owner's hive, one of them in slack). AppCompatCacheParser prints slack entries to the second; Atropos keeps their full time.
- **A jump list entry never used has no time and is not an event** (1 in the owner's lists, pinned). Its shell link's times are on the timeline.
- **Shellbags are dated by the folder's own key.** SBECmd's "LastWriteTime" is the time of the key that holds the item (the parent's), and its "FirstInteracted" the folder's own; both agree with the key times read here, attributed differently.
- **Shellbag folder names** agree for 703 of 724 folders in the owner's UsrClass.dat (679 before 15 November, when portable devices, OneDrive folders, Control Panel categories and property views were added). Of the 21 that differ, 8 are the same special folder in other words, and 11 are property views, where Atropos shows the store's display name ("Search Results in …", property 10 of the item-name set, as libfwps describes) and SBECmd another property. Two are misread here: one folder inside an archive, read as a volume, and one property-view folder.
- **UserAssist entries with no last-run time are not events** (133 in the owner's hive, against RECmd). The two tools also word known folders differently (`%SystemRoot%\System32` here, `{System}` there); the comparison is on the rest of the name.

## How to run it

```sh
python -m venv /tmp/cmpenv
/tmp/cmpenv/bin/pip install python-evtx regipy dissect.ntfs dissect.esedb dissect.regf dissect.eventlog
/tmp/cmpenv/bin/pip install --no-deps pyhindsight        # only its tables are read

atropos ingest --case /tmp/cmpcase testdata/Security.evtx testdata/NTUSER.DAT testdata/test.ntfs.dd testdata/SRUDB.dat
atropos export --case /tmp/cmpcase --format jsonl -o /tmp/cmp.jsonl

cd scripts/compare
python evtx.py     /tmp/cmp.jsonl ../../testdata/Security.evtx
python registry.py /tmp/cmp.jsonl ../../testdata/NTUSER.DAT
python ntfs.py     /tmp/cmp.jsonl ../../testdata/test.ntfs.dd
python srum.py     /tmp/cmp.jsonl ../../testdata/SRUDB.dat
python amcache.py  EXPORT.jsonl Amcache.hve
python chromium_codes.py /tmp/cmpenv/lib/python3*/site-packages/pyhindsight ../../internal/parsers/sqlite.go

# The Zimmerman tools: run each to CSV, then (standard library only)
python ez.py evtx      /tmp/cmp.jsonl evtx.csv
python ez.py prefetch  /tmp/cmp.jsonl pecmd.csv
python ez.py srum      /tmp/cmp.jsonl FOLDER_OF_SRUMECMD_CSVS
python ez.py mft       EXPORT.jsonl mftecmd.csv [EVIDENCE_ID]
python ez.py shimcache EXPORT.jsonl appcompatcache.csv
python ez.py shellbags EXPORT.jsonl USER_UsrClass.csv EVIDENCE_ID
python ez.py recycle   EXPORT.jsonl rbcmd.csv
python ez.py jumplist  EXPORT.jsonl AutomaticDestinations.csv
python ez.py lnk       EXPORT.jsonl lecmd.csv
# Plaso (on Kali, in a venv; its worker processes die there, so --single_process):
#   log2timeline --single_process --unattended --storage_file s.plaso FOLDER; psort -o json_line -w s.jsonl s.plaso
python plaso.py s.jsonl EXPORT.jsonl CASE_DIR ROOT_IN_ATROPOS_PATHS ROOT_IN_PLASO_PATHS
python evtx_set.py     EXPORT.jsonl EvtxECmd_folder.csv          # EvtxECmd -d FOLDER --csv DIR --csvf all.csv
python ez.py recmd     EXPORT.jsonl RECmd_Batch_DFIRBatch_Output.csv EVIDENCE_ID
# Shadow copies: libvshadow (pip install libvshadow-python)
python vss.py ../../testdata/vss/vss.raw
# FAT, exFAT and ext: The Sleuth Kit's fls, as a body file (standard library only)
#   fls -r -p -m / -z UTC [-o SECTOR] IMAGE > body.txt
python fls.py fat EXPORT.jsonl body.txt [EVIDENCE_ID] [p1]     # or ext
#   NTFS: the same fls line on the volume; Atropos may read the volume or its $MFT (icat VOLUME 0 > MFT)
python fls_ntfs.py EXPORT.jsonl body.txt [EVIDENCE_ID]
#   Every $FILE_NAME of a $MFT as raw FILETIMEs, from dissect.ntfs (a second opinion on names MFTECmd leaves out)
python mft_dissect_dump.py $MFT > dissect.tsv
#   A real $MFT's export is gigabytes: export only its events (--query source:mft); ez.py mft streams it
#   The bodyfile export: atropos export --format bodyfile -o atropos.body; mactime -b atropos.body -d -z UTC
#   The Sleuth Kit packaged by Kali crashes on E01 (see above): write the media out first with pyewf
# Registry: RECmd -d DIR --bn Root.reb (every key, deleted ones marked) or AllKeys.reb (whole branches); both are in scripts/compare
```

The tools are not in the repository; download them from ericzimmerman.github.io. `ez.py`'s header gives each tool's command line.

Each script exits non-zero when it finds a difference and prints the first forty. When a case holds more than one file of a kind, pass the evidence id as a third argument. Differences name keys, paths and programs from the evidence: on anything but public samples, keep the output out of the repository.

## Still to do

- **Still to compare with a Zimmerman tool:** the rest of what RECmd's batch reports (USB devices and services' values, which need a SYSTEM hive: key times, UserAssist, BAM, the recent-file and dialog lists and MountPoints2 are compared so far; RecentDocs and WordWheelQuery need a hive that has them), Amcache (AmcacheParser is not in the .NET 4 download: it needs the .NET 9 or 10 runtime installed, or `-NetVersion 10`), the change journal's records field by field (only their number is compared), event log channels other than Security. And RegRipper and Plaso. The Sleuth Kit has been run on FAT, ext and NTFS (on Kali), but not yet on exFAT or on a real `$MFT`.
- **Gaps the Zimmerman tools showed:** the modified time of shellbag items inside archives (4 on the owner's machine); the shell item kinds listed above; SRUM's energy, push-notification and `vfuprov` tables, which SrumECmd reads.
- **Not compared at all:** `$LogFile` and directory-index slack (LogFileParser, INDXParse), Notepad state, browser history values as distinct from code meanings (Hindsight run on a profile), and the whole timeline against Plaso on a disk image (done on the public artefact files, 27 November 2026; no public image holding a Windows installation is at hand).
- **`$FILE_NAME` times:** compared with `fls` on the public volumes, and with MFTECmd and dissect.ntfs on the owner's real `$MFT` (23 November); no unexplained differences.
- **Only one machine's data.** Every count above on real data is from one Windows 11 installation.
