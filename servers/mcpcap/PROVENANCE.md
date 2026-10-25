# mcpcap - provenance and audit

| | |
|---|---|
| MCP server | mcpcap: https://github.com/mcpcap/mcpcap |
| Commit | `0b7af6b29f25dd09b949c50f7a69bc493b84c2bf` (tag v0.10.0, 2026-09-30) |
| Licence | MIT, Copyright (c) 2025 danohn (`LICENSES/mcpcap-MIT.txt`) |
| Python packages | `fastmcp==3.2.0` (as in mcpcap's `uv.lock`), `scapy==2.7.0`, `requests==2.33.0` and their dependencies, hash-locked in `requirements.txt` |
| Notable licence | scapy is GPL-2.0-only; its licence text is in the image (`/opt/venv/lib/python3.13/site-packages/scapy-2.7.0.dist-info/`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |
| Local patches | none (the build writes `src/mcpcap/_version.py` with version 0.10.0, which setuptools-scm would generate from git) |

The Dockerfile fetches exactly this commit (`git fetch` of the commit ID, checked with `git
rev-parse HEAD`) and puts `src/mcpcap` on the virtual environment's path.

## Audit

**Tools:** `analyze_dns_packets`, `analyze_dhcp_packets`, `analyze_icmp_packets`,
`analyze_capinfos`, `analyze_tcp_connections`, `analyze_tcp_anomalies`,
`analyze_tcp_retransmissions`, `analyze_traffic_flow`, `analyze_sip_packets`.

**Command execution:** none - packets are parsed in-process with scapy (`rdpcap`); no
subprocess, no shell, no `eval`.

**Files:** each tool takes a local path (any path with a `.pcap`, `.pcapng` or `.cap`
extension that exists in the container; the container holds only the image and the folder
axross mounts at `/work`) or an http(s) URL.

**Network:** an http(s) URL is downloaded with `requests` to a temporary file, which is
removed afterwards. With axross's default (no network) that fails - checked: `Failed to
download PCAP file ... Failed to resolve`. Granting the network would let the model make the
server fetch arbitrary URLs (including internal ones), so the catalog entry asks for none.

**HTTP transport:** mcpcap's optional HTTP mode (bearer token, loopback by default) is not
used; axross runs it over stdio.
