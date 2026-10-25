# sleuthkit - provenance and audit

| | |
|---|---|
| MCP server | this repository, `src/server.py` (MIT, `LICENSES/axross-mcp-hub-MIT.txt`) |
| Tool | The Sleuth Kit 4.12.1 (mmls, fsstat, fls, istat, icat, mactime), Debian trixie package `sleuthkit=4.12.1+dfsg-3` |
| Tool licence | CPL-1.0 for most of the code, IPL-1.0, GPL-2+ and others for some files, `LICENSES/debian-sleuthkit-copyright.txt` |
| Python packages | `mcp==1.30.0` and its dependencies, hash-locked in `requirements.txt` |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Why an own server

No maintained, licensed MCP server for The Sleuth Kit was found in the sources searched
(see `docs/CANDIDATES.md`). The command line tools are small and well defined, so a server
that maps a few of them to tools with checked arguments is easy to audit.

## Audit

**Tools:** `partitions` (mmls -B), `filesystem_info` (fsstat), `list_files` (fls -p, with
-r / -d), `file_metadata` (istat), `read_file` (icat, bounded), `extract_file` (icat into
/out), `timeline` (fls -r -m / piped into mactime -b - -d -z UTC).

**Command execution:** argument lists, no shell, every run with a timeout (1-3600 s). The
timeline pipes fls' body file into mactime through Python (stdin), not a shell pipe.
`read_file` reads at most `max_bytes` (1 B - 1 MiB) from icat and then kills it; a watchdog
timer kills an icat that never ends.

**Arguments:** `image` must resolve to a file under `/work` and is passed as an absolute
path. `inode` must match `^[0-9]{1,20}(?:-[0-9]{1,10}-[0-9]{1,10})?$` (a number or an NTFS
address such as 64-128-1), so `4; id` or `-f` are refused. `offset` (sectors) is a bounded
integer. `extract_file`'s `name` must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (no path,
no leading dot or dash).

**Files:** images are only read (TSK opens them read-only). `extract_file` writes only to
`/out/<name>`, needs `/out` to be a writable mount, never overwrites (`lexists` check and
`open(..., "xb")`, i.e. `O_CREAT|O_EXCL`, which also refuses a symlink planted at that name)
and removes a partial file when icat fails.

**Output:** listings and timelines are cut at 200,000 characters.

**Network:** none.

**Tested with a self-made FAT12 image** (128 KiB, `mkfs.fat`): KEEP.TXT (inode 4) and a
deleted GONE.TXT (shown by fls as `_ONE.TXT`, inode 5) - both contents are read back,
including the deleted one.
