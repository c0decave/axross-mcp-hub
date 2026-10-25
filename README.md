# axross-mcp-hub

Curated, audited, container-packaged [MCP](https://modelcontextprotocol.io) servers for
**authorized** security work - reverse engineering, firmware and forensics, network
reconnaissance, web testing, OSINT, secret scanning and password cracking - built for
[axross](https://github.com/c0decave/axross), which offers this hub as a predefined MCP
source.

Every server here was read line by line before it was packaged. Where the upstream code
passed model-controlled values unchecked to a command line, read files outside the folder
it was given, or did not work inside axross's locked-down container, it was patched; each
server's `PROVENANCE.md` lists the findings and the full patch as a diff.

> **Authorized use only.** These tools scan, probe and exploit. Use them only against
> systems and data you own or have explicit, written permission to test. You are
> responsible for complying with the law and with your engagement's rules. The authors
> accept no liability for misuse.

## Servers

| Server | Category | What it does | Upstream (pinned) | Network | Folder |
|---|---|---|---|---|---|
| [radare2](servers/radare2) | Reverse engineering | radare2 6.2.4 through the official **r2mcp** 1.9.0: analysis, functions, strings, disassembly, decompilation, xrefs | radareorg/radare2-mcp, radareorg/radare2 | none | `/work` |
| [capa](servers/capa) | Reverse engineering | Mandiant **capa** 10.0.0 + capa-rules: capabilities of PE/ELF/.NET, mapped to ATT&CK and MBC | FuzzingLabs wrapper, mandiant/capa | none | `/work` |
| [floss](servers/floss) | Reverse engineering | Mandiant **FLOSS** 3.2.0: static, stack, tight and decoded (emulated) strings of PE files and shellcode | own server, mandiant/flare-floss | none | `/work` |
| [binwalk](servers/binwalk) | Firmware & forensics | **binwalk** 2.4.3: signatures, extraction, entropy, hex dumps | FuzzingLabs wrapper, OSPG/binwalk (Debian) | none | `/work`, `/out` (optional, writable) |
| [yara](servers/yara) | Firmware & forensics | **YARA** 4.5.2 with a compile-checked Yara-Rules subset, your rules or inline rules | FuzzingLabs wrapper, VirusTotal/yara (Debian) | none | `/work`, `/rules` (optional) |
| [mcpcap](servers/mcpcap) | Firmware & forensics | **mcpcap** 0.10.0: DNS, DHCP, ICMP, SIP, TCP and capinfos analysis of PCAP files | mcpcap/mcpcap | none | `/work` |
| [tshark](servers/tshark) | Firmware & forensics | Wireshark **TShark** 4.4.19: capture summary, protocol hierarchy, conversations, fields with display filters, streams, HTTP, DNS, clear-text credentials | own server, Wireshark (Debian) | none | `/work` |
| [sleuthkit](servers/sleuthkit) | Firmware & forensics | **The Sleuth Kit** 4.12.1: partitions, file systems, file listings incl. deleted files, file content by inode, MAC timeline | own server, The Sleuth Kit (Debian) | none | `/work`, `/out` (optional, writable) |
| [exiftool](servers/exiftool) | Firmware & forensics | **ExifTool** 13.25: metadata of images, documents, audio and video, read-only | joshmsimpson/exiftool_mcp (patched), ExifTool (Debian) | none | `/work` |
| [gitleaks](servers/gitleaks) | Code & secrets | **gitleaks** 8.30.1: secrets in files and in the whole git history, redacted by default | own server, gitleaks/gitleaks (built with Go 1.27) | none | `/work` |
| [john](servers/john) | Passwords & crypto | **John the Ripper** jumbo (CPU): wordlist + rules, single, incremental; hashes of zip, rar, PDF, Office, SSH, KeePass files | own server, openwall/john | none | `/work` (optional) |
| [nmap](servers/nmap) | Network recon | **Nmap** 7.95: TCP connect scans, service detection, NSE scripts | FuzzingLabs wrapper, Nmap (Debian) | full | - |
| [nuclei](servers/nuclei) | Web | ProjectDiscovery **nuclei** 3.11.1 + nuclei-templates 10.5.1 | FuzzingLabs wrapper, projectdiscovery/nuclei | full | - |
| [sqlmap](servers/sqlmap) | Web | **sqlmap** 1.10.10: SQL injection detection, enumeration, dumps | FuzzingLabs wrapper, sqlmapproject/sqlmap | full | - |
| [ffuf](servers/ffuf) | Web | **ffuf** 2.1.0 with five SecLists wordlists: directories, files, vhosts, parameters | FuzzingLabs wrapper, ffuf (Debian), SecLists | full | `/work` (optional) |
| [dnstwist](servers/dnstwist) | OSINT | **dnstwist** 20250130: look-alike domains (offline) and their DNS records | own server, elceef/dnstwist | full (scan only) | - |
| [crtsh](servers/crtsh) | OSINT | Certificate Transparency through **crt.sh**: subdomains and certificates of a domain (passive) | own server | allowlist `crt.sh:443` | - |

"FuzzingLabs wrapper": the MCP server code comes from FuzzingLabs
[mcp-security-hub](https://github.com/D4T4HUN73R/mcp-security-hub) (MIT; the original
repository is gone, the linked copy matches its archived history) at commit `0409a54`,
patched here.

Images: `ghcr.io/c0decave/axross-mcp-<name>`, always referenced by digest in
[`catalog.json`](catalog.json).

## How axross uses it

axross reads `catalog.json` (schema `axross-mcp-catalog`, version 1) as an MCP source:
Agent Settings > MCP Sources (this hub is predefined; any copy of the file can also be
added as a file or https URL), then MCP Servers > Add from Catalog. For an entry it

1. pulls `ghcr.io/c0decave/axross-mcp-<name>@sha256:...` - the catalog pins every image
   by digest, and axross refuses an entry without one;
2. asks for the folders the entry takes (`/work`, ...) and the network (default: none);
3. runs the server over stdio with rootless podman:

   ```
   podman run --rm -i --init --pull=never --log-driver=none --cap-drop=ALL \
     --security-opt=no-new-privileges --read-only \
     --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m --pids-limit=128 --memory=512m \
     --env-file=/dev/fd/N --network=none [--user=0:0 --volume=HOST:/work:ro] IMAGE@DIGEST
   ```

With network **Allowlist** (crtsh) axross adds
`--network=pasta:--no-map-gw,--no-udp,--no-icmp,--ipv4-only,-o,127.0.0.1,-T,PORT` and sets
`HTTPS_PROXY` to its own CONNECT proxy, which lets through only the hosts of the entry.

Every image here was started with exactly this line (`scripts/smoke_test.py` builds it the
way axross's `core/mcp_install.py` does) and answered `initialize`, `tools/list` and real
tool calls against local test files and a local test target; the allowlist entry was tested
through axross's own egress proxy.

## Security model

- **Containment first.** No capabilities (no `NET_RAW`: nmap does TCP connect scans only),
  no new privileges, read-only root, a small `noexec` /tmp, process and memory limits,
  rootless podman. No network unless the user grants it per server; file access only to
  the folders the user mounts, read-only by default.
- **Pinned supply chain.** Base images by digest; Debian packages by exact version; Python
  packages hash-locked (`requirements.txt`, wheels only; the two FLOSS dependencies
  without a usable wheel are built from their hash-checked sdists in a throw-away build
  stage; pip is removed from the image afterwards); upstream
  source fetched by commit ID and verified; release binaries checked against their
  published SHA-256; images published by digest.
- **Audited wrappers.** Model-controlled arguments are validated before they reach a
  command line (no value can become an option), paths must resolve under the mounted
  folder, numbers are bounded; no shell anywhere. The audits and patches are in each
  `servers/<name>/PROVENANCE.md`.
- **CI.** Every image is built, started with axross's run line, scanned with Trivy (a
  CRITICAL vulnerability with an available fix fails the build), pushed to GHCR with SBOM
  and provenance attestations, and its digest is reported.

What containment does not change: a server granted the network can reach whatever the
host can reach; the tools do what they are made for (scanning, exploiting SQL injection)
against the targets the model names. Keep axross's confirm mode on for these servers.

## Repository layout

```
servers/<name>/
  Dockerfile        pinned base, pinned tool versions, non-root user, MCP over stdio
  server.json       the catalog entry (without digest)
  src/              the MCP server source (patched upstream code or own code)
  requirements.*    Python dependencies: .in (direct) and .txt (hash-locked)
  PROVENANCE.md     upstream, commit, licences, audit, patch as diff
  LICENSES/         licence texts of the server and the bundled tools
  smoke.json        the live test: tool calls and expected results
  tools.json        the tools the server offers (CI fails when tools/list differs)
digests.json        image digests of the last published build (null = not yet published)
catalog.json        generated by scripts/make_catalog.py
scripts/            make_catalog.py, smoke_test.py, axross_smoke.py, lock.sh
tests/              hub tests; axross-smoke.json (the smoke spec of every catalog entry);
                    web_target/app.py (the local web target of the scanner specs)
docs/CANDIDATES.md  MCP servers considered for the hub, with verdicts
```

## Smoke spec for axross: `tests/axross-smoke.json`

One object per catalog entry, read by axross's own tests and by `scripts/axross_smoke.py`:
the tools the server must offer, small self-made fixture files (inline base64, gzip for
the larger ones) and the folder they are mounted at, the network to grant, a local target
to start for the scanners (`targets.web`: `python:3.14-slim` pinned by digest running
`tests/web_target/app.py`), one real call with a text its answer must contain, and one bad call
that the server must refuse with a text naming the problem. The format is documented in
`scripts/axross_smoke.py`. A hub test fails when a catalog entry has no spec, or a spec
names a tool, target, folder or file that does not exist.

## Maintenance

```
python3 -m unittest discover -s tests            # hub tests
python3 scripts/make_catalog.py --check          # catalog current and fully pinned?
python3 scripts/axross_smoke.py --check          # smoke spec covers the catalog?
python3 scripts/axross_smoke.py --run-all --from-catalog --target-host <host-only address> \
  --axross /path/to/axross                         # every server, end to end (podman)
scripts/lock.sh                                  # re-lock requirements.txt (in podman)
podman build -t local/axross-mcp-yara servers/yara
python3 scripts/smoke_test.py --image local/axross-mcp-yara \
  --spec servers/yara/smoke.json --var FIXTURES=/path/to/test/files
```

After a CI run on `main`, take its digests into the catalog:

```
scripts/make_catalog.py --ci-digests <downloaded digest-*.json> --write-digests
scripts/make_catalog.py --check --axross /path/to/axross   # with axross's Python
```

## Licence

The code of this repository is MIT ([LICENSE](LICENSE)); the FuzzingLabs-derived servers
keep FuzzingLabs' MIT copyright. The images also contain third-party tools under their own
licences (LGPL-3.0, GPL-2.0/3.0, the Nmap licence, Apache-2.0, CPL-1.0, the Perl licence,
BSD, MIT, John the Ripper's unRAR licence); see each server's
`LICENSES/` and `PROVENANCE.md`. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).
