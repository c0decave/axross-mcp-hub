# mcpcap - provenance and audit

| | |
|---|---|
| MCP server | mcpcap: https://github.com/mcpcap/mcpcap |
| Commit | `0b7af6b29f25dd09b949c50f7a69bc493b84c2bf` (tag v0.10.0, 2026-09-30) |
| Licence | MIT, Copyright (c) 2025 danohn (`LICENSES/mcpcap-MIT.txt`) |
| Python packages | `fastmcp==3.2.0` (as in mcpcap's `uv.lock`), `scapy==2.7.0`, `requests==2.33.0` and their dependencies, hash-locked in `requirements.txt` |
| Notable licence | scapy is GPL-2.0-only; its licence text is in the image (`/opt/venv/lib/python3.13/site-packages/scapy-2.7.0.dist-info/`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |
| Local patches | `patches/0001-only-files-under-work-no-urls.patch` (see Review); the build also writes `src/mcpcap/_version.py` with version 0.10.0, which setuptools-scm would generate from git |

The Dockerfile fetches exactly this commit (`git fetch` of the commit ID, checked with `git
rev-parse HEAD`), applies the patch, checks the patched file's SHA-256 and puts `src/mcpcap` on the
virtual environment's path.

## Audit

**Tools:** `analyze_dns_packets`, `analyze_dhcp_packets`, `analyze_icmp_packets`,
`analyze_capinfos`, `analyze_tcp_connections`, `analyze_tcp_anomalies`,
`analyze_tcp_retransmissions`, `analyze_traffic_flow`, `analyze_sip_packets`.

**Command execution:** none - packets are parsed in-process with scapy (`rdpcap`); no
subprocess, no shell, no `eval`.

**Files:** each tool takes a path to a capture under `/work` (`.pcap`, `.pcapng` or `.cap`); patch
0001 refuses any path whose real location (symlinks resolved) is outside `/work`. Upstream read any
such path in the container.

**Network:** none. Upstream downloads an http(s) URL with `requests` (with axross's default, no
network, that failed: `Failed to download PCAP file ... Failed to resolve`); patch 0001 refuses any
URL, so granting the network would not make the server fetch anything either.

**HTTP transport:** mcpcap's optional HTTP mode (bearer token, loopback by default) is not
used; axross runs it over stdio.

## Review

Reviewed for this repository on 2026-11-11, at exactly the pinned commit `0b7af6b2` (fetched by
commit ID into an empty folder, `git fsck` clean; never run on the review machine): every module
the image installs - the whole `src/mcpcap` package, 13 files, 3,049 lines - read line by line for
backdoors, hidden network access, telemetry, command or shell execution, code loading
(`eval`/`exec`/`pickle`/imports by name), path traversal out of `/work`, unsafe parsing, and
anything a malicious capture or a malicious MCP client could use to get past the documented
limits. The build adds `_version.py` (2 lines, written by the Dockerfile). The dependencies
(fastmcp 3.2.0, scapy 2.7.0, requests 2.33.0 and theirs, hash-locked in `requirements.txt`) are not
part of this review; scapy does the packet parsing.

| File | Lines | SHA-256 (upstream) |
|---|---:|---|
| `src/mcpcap/__init__.py` | 41 | `05ba217e655d1291d2d60065eca1c3ae26aa84e6b8afa57a5700b5f583a50cf5` |
| `src/mcpcap/cli.py` | 102 | `be454cf4b6f43984dfeb6f5625800f2df6e8084ea4638f8371fb71b66422f4ce` |
| `src/mcpcap/core/__init__.py` | 6 | `58ce464e5d3a670c2a1d33e229a601fbd87038e5dede1c871b5e85b21c12b231` |
| `src/mcpcap/core/config.py` | 74 | `a653ae76c8465ded8f4be93ad313af63fb7eed00030e3d997303e91ea0b1ba8e` |
| `src/mcpcap/core/server.py` | 103 | `b0028d788968b5ee30e767f5687f338dcc76ffc5f2cb649765fcb282419943b5` |
| `src/mcpcap/modules/__init__.py` | 19 | `c826001a5c27de796f206680494bc739e07c09156d160020f041daa5dc2e7003` |
| `src/mcpcap/modules/base.py` | 153 | `e8c1d21c03b8eb8c38cb845e966986e348fda9ad742612935e7ab342d0a0e788` (patched: below) |
| `src/mcpcap/modules/capinfos.py` | 126 | `f5de0a3de12c5e4a5eaa637c673095d84e3e9e5c15f6b1eddd8322d05555d78c` |
| `src/mcpcap/modules/dhcp.py` | 352 | `75354fe4497e2c5902de56d210043b3b4c9883938dba1034db8981f5af3d30eb` |
| `src/mcpcap/modules/dns.py` | 339 | `d5ac5ec358bfe9d5281b469d2fcc503be8ead6d9a7651bd14e8f0e72372cdcf6` |
| `src/mcpcap/modules/icmp.py` | 373 | `d10ce0f13c5d9ca10397e75455684c412b0fdad5c97617e384f9a2aa4cefa581` |
| `src/mcpcap/modules/sip.py` | 319 | `f1c6fa0989f43f2cacf8b26b6a978e7d8f37890f3bb03734981e5cd165fca8f8` |
| `src/mcpcap/modules/tcp.py` | 1,042 | `2fcaf12cc23dabf138c892a7c9a58b21c28aa56073aaa4614ecc4c7bd21d4660` |

**No backdoor, no telemetry, no hidden network access found.** No `subprocess`, shell, `eval`,
`exec`, `pickle`, `marshal`, dynamic import or socket anywhere; the only network code is the URL
download in `base.py` (finding 1, now unreachable). The only environment variable read is
`MCPCAP_AUTH_TOKEN`, and only for the HTTP transport (`core/config.py:36-38`), which this image does
not use (stdio; the bearer check in `core/server.py:18-29` compares SHA-256 digests in constant
time). Files are opened only by scapy's `rdpcap`/`PcapReader` on the given path and by the
download (writes a temporary file). The 14 MCP prompts the modules register
(`setup_prompts` in `dns.py`, `dhcp.py`, `icmp.py`, `sip.py`, `tcp.py`) are fixed analysis
instructions, nothing hidden. The analysis itself (`dns.py`, `dhcp.py`, `icmp.py`, `sip.py`,
`tcp.py`, `capinfos.py`) only reads scapy fields, counts and builds dictionaries; the SIP regular
expressions (`sip.py:135`, `sip.py:144`) are linear; a malformed packet raises inside the
per-file `try` and comes back as an error text.

**Findings, and what this image does about them:**

1. **Any http(s) URL was downloaded (medium; no network here).** A `pcap_file` starting with
   `http://` or `https://` is fetched with `requests.get` (`base.py:60-61`, `base.py:126-153`): any
   host, redirects followed, no size limit, written to `/tmp` (a tmpfs, i.e. memory). With a
   network, the model could make the server fetch internal addresses (SSRF) or fill memory. Under
   the hardened run line (no network) it fails, as checked before. **Patch 0001:** any value with
   `://` is refused before anything happens.
2. **Any `*.pcap` path in the container was read, and any path's existence was told (low).**
   `_handle_local_analysis` (`base.py:97-124`) accepts every path with a `.pcap`, `.pcapng` or
   `.cap` extension, follows symlinks, and checks existence before the extension, so its answer
   (`PCAP file not found` or `not a supported PCAP file`) told whether any path exists. In the
   container that is only the image and `/work`, nothing secret, but not the documented limit.
   **Patch 0001:** the real path (symlinks resolved) must lie under `/work`, checked before the file
   is even looked at; the resolved path is what is read.
3. **Memory and CPU (informational).** Five modules read the whole capture with `rdpcap`
   (`dns.py:47`, `dhcp.py:46`, `icmp.py:47`, `sip.py:67`, `capinfos.py:197`; `--max-packets` only
   shortens the list afterwards), `tcp.py:195-203` stops reading at the limit, and the
   retransmission tracker merges intervals in a list (`tcp.py:1003-1042`, quadratic at worst). A
   large or crafted capture costs memory and time, bounded by the container's limits; not changed.
4. **The capture's text goes to the model (informational).** DNS names, SIP headers (User-Agent,
   From, ...), DHCP option strings and scapy summaries are returned verbatim
   (`dns.py:130-185`, `sip.py:159-183`, `dhcp.py:161-203`): someone else wrote them - data, not
   instructions (the catalog notes say so).
5. **Not used here (informational).** The HTTP transport and `--allow-unauthenticated-http`
   (`cli.py`, `core/config.py`, `core/server.py`); the `setuptools_scm` fallback in `__init__.py:30-37`
   (it would run git) is not reached because the build writes `_version.py`. The tools' docstrings
   still offer URLs; the patched server refuses them with a clear message.

### The patch (`patches/`, applied with `patch -p1 --fuzz=0`; the build then checks the result)

| Patch | SHA-256 | What |
|---|---|---|
| `0001-only-files-under-work-no-urls.patch` | `57c81e05edc68c6d8f3c54fc2e25365e52e0ee3e275d666637925a7dc4f39b21` | `src/mcpcap/modules/base.py`: `analyze_packets` (which every tool goes through, `tcp.py:173-182` included) refuses any value with `://` and any path whose real location is outside `/work`, then reads the resolved path (findings 1 and 2) |

The patched `src/mcpcap/modules/base.py` must have SHA-256
`3117917211e39fa387600735858f1728ecc511020ca69ea04e0633e7a16d771b` or the build stops. The patch was
applied to the pinned commit here (`git apply --check`, then the hash above), and the path check's
behaviour (`os.path.realpath` + `commonpath`: `/work/../etc/x.pcap`, `/workx/a.pcap`, relative and
empty paths refused, `/work/./b.cap` taken) was checked with Python's own functions; the server
runs only in CI, which builds the image and runs the smoke spec (`/etc/passwd` refused with
"is outside /work", a URL with "URLs are refused").

**Verdict:** reviewed completely; with patch 0001 nothing found remains open. Signed once a CI run
has built this Dockerfile and its smoke runs passed for that digest.
