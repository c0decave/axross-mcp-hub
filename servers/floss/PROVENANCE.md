# floss - provenance and audit

| | |
|---|---|
| MCP server | this repository, `src/server.py` (MIT, `LICENSES/axross-mcp-hub-MIT.txt`) |
| Tool | Mandiant FLOSS 3.2.0 (`flare-floss==3.2.0` from PyPI, hash-locked), https://github.com/mandiant/flare-floss |
| Tool licence | Apache-2.0 (`LICENSES/flare-floss-Apache-2.0.txt`); its emulator vivisect is Apache-2.0 as well |
| Python packages | `mcp==1.30.0`, `flare-floss==3.2.0` and their dependencies, hash-locked in `requirements.txt`; build-only `setuptools`, `pybind11` hash-locked in `requirements-build.txt` |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Why an own server

No FLOSS MCP server was found in the sources searched (MCP registry results, the
R00T-Kim awesome list, Docker's mcp namespace, FuzzingLabs mcp-security-hub). FLOSS has a
JSON output mode, so a server around its CLI is small.

## Build note: two packages built from source, in a separate stage

Two dependencies of FLOSS have no usable wheel for Python 3.13 on Linux:
`binary2strings==0.1.13` publishes only an sdist (a pybind11 C++ extension), and
`halo==0.0.31`'s only wheel is for Python 2. They are built into wheels in a separate
`wheel` stage: `pip wheel --require-hashes --no-deps --no-build-isolation`, i.e. from the
hash-checked sdists of `requirements.txt`, with the hash-locked build requirements from
`requirements-build.txt` and without downloading anything else. The final image installs
all wheels from that stage with `--no-index --no-deps` and has no compiler, no pip and no
build requirements. Their build scripts run only in the throw-away stage.

## Audit

**Tools:** `floss_strings`, `floss_languages` (static text, no process).

**Command execution:** `floss -j --disable-progress -n MIN --format F --only TYPES -- PATH`
as an argument list, no shell, timeout 1-3600 s (default 600). `--` ends the options
before the path.

**Arguments:** `filepath` must resolve under `/work` (passed absolute); `only` a non-empty
subset of `static`, `stack`, `tight`, `decoded`; `file_format` one of `auto`, `pe`,
`sc32`, `sc64`; `min_length` 3-64; `max_strings` 1-50000 per type.

**Sample handling:** FLOSS emulates code with vivisect in-process; the sample is never
executed. Emulation of large samples needs much memory and time; axross's 512 MiB limit
applies.

**Network:** none. **Files:** reads only the given sample.
