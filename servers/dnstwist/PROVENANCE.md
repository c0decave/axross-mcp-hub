# dnstwist - provenance and audit

| | |
|---|---|
| MCP server | this repository, `src/server.py` (MIT, `LICENSES/axross-mcp-hub-MIT.txt`) |
| Tool | dnstwist 20250130 (`dnstwist==20250130` from PyPI, hash-locked), https://github.com/elceef/dnstwist (tag 20250130, commit `4e6e477e95049067a7fe41fd8512e332abe26e95`) |
| Tool licence | Apache-2.0 (`LICENSES/dnstwist-Apache-2.0.txt`) |
| Python packages | `mcp==1.30.0`, `dnstwist==20250130`, `dnspython==2.8.0` and their dependencies, hash-locked in `requirements.txt` |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Why an own server

The MCP servers for dnstwist that were considered - BurtTheCoder/mcp-dnstwist, which
FuzzingLabs mcp-security-hub wraps in `osint/dnstwist-mcp` - start dnstwist with `docker
run` through the Docker CLI, i.e. they need the Docker socket (control over the host's
container engine) and cannot work inside axross's capability-free container. dnstwist is a
Python library, so this server calls it directly.

## Audit

**Tools:** `dnstwist_fuzzers`, `dnstwist_permutations` (offline), `dnstwist_scan` (DNS).

**Command execution:** none - `dnstwist.Fuzzer` and `dnstwist.run(**kwargs)` are called
in-process (`run` in a worker thread, so dnstwist installs no signal handlers; anything it
prints goes to stderr, never to the MCP channel on stdout).

**Arguments:** `domain` must be a domain name (letters, digits, hyphens, dots; never a
leading `-`); `fuzzers` must be dnstwist's algorithm names; `nameservers`: up to 8 IPv4
addresses or `https://host/dns-query` URLs; `threads` 1-32; `max_results` 1-5000. dnstwist's
web, WHOIS, GeoIP, banner, LSH and screenshot features are not reachable.

**Network:** `dnstwist_scan` sends DNS queries (A, AAAA, NS, MX) for every permutation to the
container's resolver or the given name servers, so axross's network must be Full; without it
every domain reads as `!ServFail`. `dnstwist_permutations` needs no network.

**Files:** none.
