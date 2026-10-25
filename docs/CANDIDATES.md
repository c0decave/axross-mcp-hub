# MCP server candidates for axross-mcp-hub

Which MCP servers (or tools worth wrapping) this hub should also carry, judged against what
axross allows a catalog server: rootless podman with **no capabilities, read-only root, a
64 MiB `noexec` /tmp, at most 128 processes and 512 MiB memory**, no network unless the user
grants **Allowlist** (HTTPS CONNECT to listed `host:port` through axross's proxy,
`HTTPS_PROXY` set) or **Full**, user files only as mounted folders, secrets only as
environment variables from axross's keyring.

State: 2026-10-25. Sources: the R00T-Kim awesome-offensive-mcp list (CC0, commit
`28f9c0f`), the official MCP registry (470 results of security-related queries), Docker's
`mcp/*` namespace (the 100 most-pulled repositories), the FuzzingLabs mcp-security-hub copy
(`0409a54`), upstream repositories (licences read from the GitHub API or the licence file on
2026-10-25 unless marked *not re-checked*), and the coordinator's suggestions.

**Evidence marks:** *tested* = built and run here with axross's exact run line; everything
else is an assessment from the source, documentation and the run-line limits, not a
measurement - the "needs work" items name what has to be measured first.

**Not duplicated:** axross's built-in catalog already ships Docker's `mcp/git`,
`mcp/filesystem`, `mcp/fetch`, `mcp/sqlite`, `mcp/memory`, `mcp/sequentialthinking`,
`mcp/time`, `mcp/everything`, `mcp/vuln-nist` and `mcp/shodan`; candidates that only repeat
them are left out.

## 1. In the hub

| # | Server | Upstream, licence | Category | Fits the run line | Needs | Status |
|---|---|---|---|---|---|---|
| 1-9 | radare2, capa, binwalk, yara, mcpcap, nmap, nuclei, sqlmap, dnstwist | see each `PROVENANCE.md` | RE, forensics, network, web, OSINT | yes (*tested*) | `/work`; nmap/nuclei/sqlmap network Full | published (first round) |
| 10 | **tshark** | own server; Wireshark 4.4.19 (GPL-2.0+) | forensics / network | yes (*tested*) | `/work` | built this round |
| 11 | **sleuthkit** | own server; The Sleuth Kit 4.12.1 (CPL-1.0 and others) | forensics | yes (*tested*) | `/work`, optional writable `/out` | built this round |
| 12 | **exiftool** | joshmsimpson/exiftool_mcp (MIT), patched: tag names reached ExifTool's `-if` (Perl code execution, reproduced) | forensics / OSINT | yes (*tested*) | `/work` | built this round |
| 13 | **gitleaks** | own server; gitleaks 8.30.1 (MIT), built with Go 1.27 | code & secrets | yes (*tested*) | `/work` | built this round |
| 14 | **floss** | own server; Mandiant FLOSS 3.2.0 (Apache-2.0) | RE / malware | yes (*tested*) | `/work` | built this round |
| 15 | **john** | own server; John the Ripper jumbo (GPL-2.0+, relaxed terms) | passwords & crypto | yes (*tested*) | optional `/work` | built this round |
| 16 | **ffuf** | FuzzingLabs ffuf-mcp (MIT), patched; ffuf 2.1.0 (MIT); SecLists (MIT) | web | yes (*tested*) | network Full | built this round |
| 17 | **crtsh** | own server; crt.sh | OSINT | yes (*tested*, through axross's proxy) | Allowlist `crt.sh:443` | built this round |

## 2. Build next (ranked)

| Rank | Candidate | Upstream, licence | Category | What it does | Fits the run line | Needs | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | **oletools + pdfid/pdf-parser** ("maldoc") | decalage2/oletools (BSD-2-Clause); DidierStevens/DidierStevensSuite `pdfid.py`, `pdf-parser.py` (public domain, stated in the source) | file formats / malware | VBA macros, DDE, OLE objects, RTF objects of Office files; PDF keywords, objects, streams | yes: pure Python, offline, small | `/work` | **build now** - no MCP server exists in the sources; an own server over olevba/mraptor/oleid/rtfobj/msodde and pdfid/pdf-parser (`-a`, `-o`, `-f` only, no `--generate`) |
| 2 | **LIEF inspection** | lief-project/LIEF (Apache-2.0, PyPI wheels) | binary analysis | ELF/PE/Mach-O headers, sections, imports/exports, relocations, signatures, entropy | yes: wheels, offline, in-process | `/work` | **build now** - small own server; complements radare2 for quick triage |
| 3 | **Zeek on PCAPs** | zeek/zeek (BSD-3-Clause per `COPYING`) | network forensics | `zeek -r` writes conn/dns/http/ssl/files logs from a capture | likely: offline, logs into a temporary folder; memory modest for small captures (*not measured*) | `/work` | **build now** - Debian package or official build; return selected logs as JSON; cap capture size |
| 4 | **osv-scanner** | google/osv-scanner (Apache-2.0) | code / supply chain | known vulnerabilities of lockfiles and SBOMs in a folder | yes: static Go binary | `/work`; Allowlist `api.osv.dev:443` | **build now** - build from source with a current Go (release binaries carry the Go of their release); offline mode with a baked DB only if size allows |
| 5 | **ProjectDiscovery httpx / subfinder / dnsx / katana** | projectdiscovery/* (MIT) | web / OSINT recon | HTTP probing, passive subdomains, DNS resolution, crawling | yes for httpx/subfinder/dnsx/katana standard mode; katana `-headless` needs Chrome (memory) - off | network Full; optional API keys for subfinder sources as env secrets | **build now** - patch FuzzingLabs `reconnaissance/pd-tools-mcp` or own server; build from source with current Go |
| 6 | **sslyze** | nabla-c0d3/sslyze (AGPL-3.0, wheels incl. nassl) | network / crypto | TLS versions, ciphers, certificate chain, known TLS flaws, JSON output | yes: Python, in-process | network Full (arbitrary `host:port`) | **build now** - AGPL-3.0 is fine for redistribution with source (the hub is public); preferred over testssl.sh (see 3.) |
| 7 | **hash identification** (name-that-hash) | bee-san/Name-That-Hash (GPL-3.0) | passwords & crypto | which hash type a string is, with john/hashcat mode names | yes: pure Python, offline | none | **build now as a tool of the john server** (`identify_hash`), not a server of its own |
| 8 | **Nikto** | FuzzingLabs `web-security/nikto-mcp` (MIT); Nikto (GPL-2.0, Debian; *not re-checked*) | web | web server misconfiguration scan | yes: Perl, Debian package | network Full | **build next** - same patch pattern as nuclei (target validation, no raw options) |
| 9 | **searchsploit (index only)** | FuzzingLabs `exploitation/searchsploit-mcp` (MIT); exploit-db (GPL-2.0, *not re-checked*) | vulnerability research | search the Exploit-DB index by product/CVE | yes, if only `files_exploits.csv`/`files_shellcodes.csv` are baked | none | **build next** - search and metadata only; no exploit code in the image |
| 10 | **VirusTotal (official)** | VirusTotal/virustotal-mcp (Apache-2.0, commit `173f464` read) | threat intel | hash/URL/domain/IP reports | yes | Allowlist `www.virustotal.com:443`; `VT_API_KEY` as secret | **build next** - needs an API key to test; hash lookups only by default (no file upload of user data without a confirm) |

## 3. Needs work (buildable after a measurement or a design decision)

| Candidate | Upstream, licence | Category | Blocker under the run line | What would make it work | Verdict |
|---|---|---|---|---|---|
| **Volatility 3** | volatilityfoundation/volatility3 (**Volatility Software License 1.0**, read); MCP: bornpresident/Volatility-MCP-Server (MIT, last push 2025-07) | memory forensics | Windows symbol tables are downloaded at run time (Microsoft symbol server) and cached under `HOME`; real memory images likely exceed 512 MiB of RSS for some plugins; VSL is not an OSI licence - redistribution terms must be read first | bake the official symbol packs (size!), cache into writable `/out`, own server with a plugin allowlist; measure memory on a 4-8 GB image | **needs work** (licence review + memory measurement) |
| **ClamAV** | Cisco-Talos/clamav (GPL-2.0) | malware signatures | the full signature set (main + daily) loaded by `clamscan` most likely needs more than 512 MiB (*not measured*); baked signatures age within days; signature redistribution terms to be checked | measure RSS with the full DB; if over the limit, offer only with an axross per-server memory override; freshclam only with Allowlist `database.clamav.net:443` and a writable DB folder | **needs work** |
| **Suricata on PCAPs** | OISF/suricata (GPL-2.0); ET Open rules (licence *not re-checked*) | network forensics | rule loading of the full ET Open set is memory-heavy (*not measured*); rules age | bake a pinned ET Open snapshot, measure `suricata -r` RSS; or a reduced rule set | **needs work** - Zeek (2.3) first |
| **semgrep** | semgrep/semgrep (LGPL-2.1); official `semgrep mcp` | code analysis | default rules come from the Semgrep registry (network, and the registry rules are under the Semgrep Rules License, not OSI); semgrep-core memory on large repos | `--metrics=off`, offline `--config` with OSI-licensed or own rules baked; measure memory | **needs work** (rule licensing) |
| **Trivy fs / SBOM** | aquasecurity/trivy (Apache-2.0); aquasecurity/trivy-mcp (MIT, last push 2025-12) | code / supply chain | the vulnerability DB (hundreds of MB unpacked) does not fit the 64 MiB /tmp; baked into the image it ages daily; memory of the DB access to be measured | bake the DB read-only with `--skip-db-update --cache-dir` in the image, or download into writable `/out` with Allowlist `mirror.gcr.io:443` / `ghcr.io:443`; measure | **needs work** - osv-scanner (2.4) covers the lockfile case with less weight |
| **testssl.sh** | testssl/testssl.sh (GPL-2.0; moved from drwetter) | network / crypto | bash + many subshells and openssl processes - close to the 128-process limit (*not measured*) | measure pids; sslyze (2.6) has no such problem | **needs work** |
| **jadx / apktool** | skylot/jadx (Apache-2.0), iBotPeaches/Apktool (Apache-2.0); jadx-mcp-plugin (no licence file - not redistributable; a GUI plugin) | Android RE | JVM decompilation of real APKs usually needs well over 512 MiB heap | own server with `-Xmx400m` for small apps, apktool decode first; offer larger apps only with a memory override | **needs work** |
| **Ghidra headless** | NationalSecurityAgency/ghidra (Apache-2.0); pyghidra-mcp (needs chromadb, which downloads an embedding model at run time - checked in chromadb 1.4.1); LaurieWired/GhidraMCP (Apache-2.0, a GUI plugin) | RE | JVM analysis beyond small binaries exceeds 512 MiB; the project database must be writable (64 MiB /tmp too small for larger binaries) | own server on pyghidra `analyzeHeadless` without chromadb, project in writable `/out`, memory override in axross | **needs work** (axross memory override first) |
| **whois / RDAP** | own server | OSINT | port-43 whois is not HTTP, so the allowlist proxy cannot carry it; RDAP bootstrap redirects to many registry hosts, and a catalog entry allows at most 16 | RDAP-only server with the RIR and major gTLD RDAP hosts allowlisted (`rdap.arin.net`, `rdap.db.ripe.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net`, `rdap.verisign.com`, ...), others reported as "not allowed"; or network Full | **needs work** (host list) |
| **maigret** | soxoj/maigret (MIT); MCP: BurtTheCoder/mcp-maigret and FuzzingLabs maigret-mcp start it through the Docker socket | OSINT (people) | the existing servers need the Docker socket; maigret itself checks thousands of sites (network Full, long runs) and builds dossiers on persons | own server calling maigret in-process, top-N sites by default, bounded time; privacy note in the entry | **needs work** (and a policy decision on people-search) |
| **Slither** | trailofbits/slither (AGPL-3.0, *not re-checked*) | smart contracts | needs `solc` compilers, normally downloaded at run time | bake a few pinned solc versions | **needs work** |
| **ZAP** | zaproxy (Apache-2.0, *not re-checked*) | web | Java daemon, memory | measure; nuclei/ffuf/nikto cover the scripted part | **needs work** |
| **whatweb** | FuzzingLabs `reconnaissance/whatweb-mcp`; WhatWeb (GPL-2.0, *not re-checked*) | web recon | Ruby, fine under the run line (*not tested*) | patch like nuclei; overlaps with httpx tech detection | **needs work** (low priority) |
| **MalwareBazaar** | mytechnotalent/MalwareBazaar_MCP (*not re-checked*) | threat intel | downloading samples would put malware into the user's folder | metadata/hash queries only, Allowlist `mb-api.abuse.ch:443` | **needs work** |
| **prowler** | FuzzingLabs `cloud-security/prowler-mcp`; prowler (Apache-2.0, *not re-checked*) | cloud | cloud credentials, many API hosts | Allowlist per cloud, credentials as secrets | **needs work** |

## 4. Not suitable (and why)

| Candidate | Upstream, licence | Reason |
|---|---|---|
| masscan | robertdavidgraham/masscan (AGPL-3.0) | raw packets need `NET_RAW`, which axross never grants; nmap's connect scan covers the use case |
| hashcat (FuzzingLabs hashcat-mcp; MorDavid/hashcat-mcp, no licence file) | hashcat (MIT, *not re-checked*) | no GPU in the container; the CPU path needs an OpenCL runtime that compiles and loads kernels at run time - not expected to work with `noexec` /tmp; John the Ripper (15) instead |
| IDA Pro MCP, Binary Ninja MCP | proprietary host applications | need a licensed desktop application running on the host |
| Burp Suite MCP | PortSwigger/mcp-server (GPL-3.0) | needs a running Burp Suite on the host |
| GhidraMCP (LaurieWired) | Apache-2.0 | plugin for a GUI Ghidra on the host (see Ghidra headless in 3.) |
| BloodHound MCP | MorDavid/BloodHound-MCP-AI (*not re-checked*) | needs a running BloodHound/Neo4j server with collected data |
| Metasploit MCP | GH05TCREW/MetasploitMCP (Apache-2.0) | needs `msfrpcd` running; exploitation with listeners and reverse connections does not fit a stdio, no-capability container |
| MobSF MCP | pullkitsan/mobsf-mcp-server (*not re-checked*) | needs a MobSF server (heavy, own database) |
| WireMCP | 0xKoda/WireMCP (MIT, JavaScript) | live capture needs `NET_RAW`/`NET_ADMIN`; reading captures is covered by tshark (10) and mcpcap |
| bx33661/Wireshark-MCP | MIT (*not re-checked*) | about 17,700 lines for the same job as tshark (10) |
| stoyky/mitre-attack-mcp | no licence file in the repository (commit `9ebd694` read) | not redistributable |
| CodeQL MCP | JordyZomer/codeql-mcp; CodeQL CLI | the CodeQL CLI's licence limits use (open source / research), not suitable for a general hub |
| GDB/LLDB/pwndbg/Frida MCPs | various | they execute the analysed program; this hub analyses samples without running them |
| Docker `mcp/git`, `filesystem`, `fetch`, `sqlite`, `memory`, `sequentialthinking`, `time`, `everything`, `vuln-nist`, `shodan` | Docker | already in axross's built-in catalog |
| Browser automation (Playwright, Puppeteer, Chrome DevTools) | various | a browser does not fit 512 MiB reliably; Docker ships `mcp/playwright` for users who want it |
| SaaS lookups (OTX, ZoomEye, Crunchbase, Shodan variants) | various | API-key front ends of paid services; low value over the existing `mcp/shodan`; can be added on request with an allowlist |
| Database clients (Postgres, MySQL, Redis, MongoDB MCPs) | various | general tools, not security-specific; Docker ships several |
| RoadRecon MCP | atomicchonk/roadrecon_mcp_server (*not re-checked*) | needs Azure/Entra credentials and a collected database; out of scope |
