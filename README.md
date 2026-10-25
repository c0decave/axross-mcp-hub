# axross-mcp-hub

Curated, audited, container-packaged [MCP](https://modelcontextprotocol.io) servers for
**authorized** security work - reverse engineering, firmware and forensics, network
reconnaissance, web testing and OSINT - built for
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
| [binwalk](servers/binwalk) | Firmware & forensics | **binwalk** 2.4.3: signatures, extraction, entropy, hex dumps | FuzzingLabs wrapper, OSPG/binwalk (Debian) | none | `/work`, `/out` (optional, writable) |
| [yara](servers/yara) | Firmware & forensics | **YARA** 4.5.2 with a compile-checked Yara-Rules subset, your rules or inline rules | FuzzingLabs wrapper, VirusTotal/yara (Debian) | none | `/work`, `/rules` (optional) |
| [mcpcap](servers/mcpcap) | Firmware & forensics | **mcpcap** 0.10.0: DNS, DHCP, ICMP, SIP, TCP and capinfos analysis of PCAP files | mcpcap/mcpcap | none | `/work` |
| [nmap](servers/nmap) | Network recon | **Nmap** 7.95: TCP connect scans, service detection, NSE scripts | FuzzingLabs wrapper, Nmap (Debian) | full | - |
| [nuclei](servers/nuclei) | Web | ProjectDiscovery **nuclei** 3.11.1 + nuclei-templates 10.5.1 | FuzzingLabs wrapper, projectdiscovery/nuclei | full | - |
| [sqlmap](servers/sqlmap) | Web | **sqlmap** 1.10.10: SQL injection detection, enumeration, dumps | FuzzingLabs wrapper, sqlmapproject/sqlmap | full | - |
| [dnstwist](servers/dnstwist) | OSINT | **dnstwist** 20250130: look-alike domains (offline) and their DNS records | own server, elceef/dnstwist | full (scan only) | - |

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

Every image here was started with exactly this line (`scripts/smoke_test.py` builds it the
way axross's `core/mcp_install.py` does) and answered `initialize`, `tools/list` and real
tool calls against local test files and a local test target.

## Security model

- **Containment first.** No capabilities (no `NET_RAW`: nmap does TCP connect scans only),
  no new privileges, read-only root, a small `noexec` /tmp, process and memory limits,
  rootless podman. No network unless the user grants it per server; file access only to
  the folders the user mounts, read-only by default.
- **Pinned supply chain.** Base images by digest; Debian packages by exact version; Python
  packages hash-locked (`requirements.txt`, wheels only, no build scripts run; pip is
  removed from the image afterwards); upstream
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
digests.json        image digests of the last published build (null = not yet published)
catalog.json        generated by scripts/make_catalog.py
scripts/            make_catalog.py, smoke_test.py, lock.sh
tests/              tests of make_catalog.py
```

## Maintenance

```
python3 -m unittest discover -s tests            # make_catalog tests
python3 scripts/make_catalog.py --check          # catalog current and fully pinned?
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
licences (LGPL-3.0, GPL-2.0/3.0, the Nmap licence, Apache-2.0, BSD, MIT); see each server's
`LICENSES/` and `PROVENANCE.md`. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).
