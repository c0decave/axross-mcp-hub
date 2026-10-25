# john - provenance and audit

| | |
|---|---|
| MCP server | this repository, `src/server.py` (MIT, `LICENSES/axross-mcp-hub-MIT.txt`) |
| Tool | John the Ripper jumbo, https://github.com/openwall/john, branch bleeding-jumbo, commit `5184bc0b8c105f8c5978b112e723d65b2de3e63e` (2026-10-11), fetched by commit and verified |
| Tool licence | GPL-2.0-or-later with relaxed terms for many components (`LICENSES/john-LICENSE.txt`, `LICENSES/john-COPYING-GPL-2.0.txt`); the bundled unRAR code is under its own licence, which forbids using it to re-create the RAR compression algorithm (`LICENSES/john-unrar-notice.txt`, from `src/unrar.h`) |
| Build | `./configure --disable-native-tests --disable-opencl` (portable, no `-march=native`, CPU only), in a build stage of the same Debian base |
| Python packages | `mcp==1.30.0` and its dependencies, hash-locked in `requirements.txt` (the *2john Python helpers use the same venv) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Why an own server and John instead of hashcat

The hashcat MCP servers (FuzzingLabs `password-cracking/hashcat-mcp`, MorDavid/hashcat-mcp)
need hashcat with an OpenCL or CUDA runtime. axross's container has no GPU device, and on a
CPU hashcat needs an OpenCL runtime such as POCL, which compiles kernels at run time into
shared objects and loads them - with `HOME` and the only writable place on the `noexec`
/tmp that is not expected to work (not tested). John the Ripper's CPU formats need none of
that. No John the Ripper MCP server was found in the sources searched (MCP registry
results, the R00T-Kim awesome list, Docker's mcp namespace, FuzzingLabs mcp-security-hub).

## Audit

**Tools:** `crack` (wordlist + rules, single, incremental), `extract_hash` (zip2john,
rar2john, pdf2john.py, office2john.py, ssh2john.py, keepass2john), `list_formats`.

**Command execution:** argument lists, no shell, every run with a timeout. `crack` writes
the hashes into a file in a private temporary folder (never onto a command line) and runs
`john --session=<tmp>/session --max-run-time=N --no-log --pot=<tmp>/john.pot [--format=F]
<mode> <hashfile>`, then `john --show` with the same pot file. The temporary folder - pot
file included - is removed after each call, so nothing cracked is kept. The environment is
reduced to `PATH` and `HOME=/tmp`; ANSI colour codes are stripped from the answer.

**Arguments:** `hashes` 1-10,000 single lines of at most 16 KiB; `format` must match
`^[A-Za-z0-9_-]{1,40}$` (so `dynamic=md5($p)` expressions and options are refused);
`mode` one of three; a wordlist must resolve to a file under `/work` (default: the bundled
`password.lst`); `max_seconds` 1-1800; `kind` one of six helpers; `filepath` under `/work`.

**Resources:** `OMP_NUM_THREADS=4`; axross's 512 MiB and 128-process limits apply.

**Network:** none.
