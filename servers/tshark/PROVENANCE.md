# tshark - provenance and audit

| | |
|---|---|
| MCP server | this repository, `src/server.py` (MIT, `LICENSES/axross-mcp-hub-MIT.txt`) |
| Tool | TShark and capinfos 4.4.19 (Wireshark), Debian trixie package `tshark=4.4.19-0+deb13u1` |
| Tool licence | GPL-2.0-or-later (some parts under other GPL-compatible terms), `LICENSES/debian-tshark-copyright.txt` |
| Python packages | `mcp==1.30.0` and its dependencies, hash-locked in `requirements.txt` |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Why an own server

The Wireshark MCP server that was considered, bx33661/Wireshark-MCP, is about 17,700 lines
of Python - too much to audit for reading capture files. Live capture is out of scope
anyway: it needs `NET_RAW` / `NET_ADMIN`, which axross never grants. This server only reads
capture files, with a small set of tools whose every argument is checked.

## Audit

**Tools:** `pcap_info` (capinfos -M), `protocol_hierarchy` (-z io,phs), `conversations`
(-z conv), `endpoints` (-z endpoints), `packets` (summaries, chosen fields with -T fields,
or -V), `follow_stream` (-z follow), `http_requests`, `dns_queries`, `credentials`
(-z credentials).

**Command execution:** `subprocess.run` with an argument list - no shell - and a timeout
(1-3600 s). tshark is always started as `tshark -n -r <file>`: it reads a file only, never
captures, never resolves names (no DNS from the container).

**Arguments:** `pcap` must resolve (realpath, symlinks followed) to a file under `/work` and
is passed as an absolute path, so it can never be an option. A display filter is one line
(no NUL/CR/LF, at most 2000 characters) passed as the value of `-Y` or as the last part of a
`-z` tap argument - never as an argument of its own. Field names must match
`^[a-z0-9_][a-z0-9_.-]{0,99}$` (at most 40); `kind`, `protocol` and `mode` are chosen from
fixed lists; counts and stream indexes are bounded integers.

**Files:** reads only the given capture. tshark's per-user configuration and plugin folders
are under `HOME=/tmp` (empty tmpfs), so no profile, preference or Lua plugin from outside
the image is loaded.

**Output:** every answer is cut at 200,000 characters (the answer says how much was cut).

**Network:** none needed.

**Root:** when axross mounts a folder it runs the container as its root user (`--user=0:0`,
still without capabilities); tshark then prints a warning about running as root and works.
