# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Report a vulnerability** button
(Security tab of https://github.com/c0decave/axross-mcp-hub, private vulnerability
reporting). Do not open a public issue for a vulnerability. Include the server, the image
digest, what an attacker controls (tool arguments, a file, a scanned target's answers) and
what they gain.

We aim to acknowledge a report within 7 days and to publish a fixed image, with a new digest
in `catalog.json`, as soon as a fix is verified.

## Scope

In scope:

- the MCP servers in `servers/*/src` - argument validation, path confinement, anything that
  lets a tool call or a processed file escape the intended behaviour;
- the Dockerfiles and the published images `ghcr.io/c0decave/axross-mcp-*` (a pinned
  component with a known vulnerability, a wrong user, a missing pin);
- `scripts/make_catalog.py` and `catalog.json` (anything that could make axross pull an image
  other than the one reviewed).

Out of scope here (report upstream): vulnerabilities inside the bundled tools themselves -
radare2, r2mcp, capa, binwalk and its extractors, YARA, mcpcap/scapy, Nmap, nuclei and its
templates, sqlmap, dnstwist - unless our packaging makes them reachable in a way upstream
does not. Each server's `PROVENANCE.md` names the upstream project and the pinned commit.

## The model behind these images

- The images run under axross's container flags: no capabilities, no new privileges,
  read-only root file system, `noexec` /tmp, process and memory limits, rootless podman,
  no network unless granted, only the folders the user mounts.
- Tool arguments come from a language model and are treated as untrusted; files and scan
  targets are untrusted input as well.
- Images are referenced by digest only. A digest in `catalog.json` changes only through
  `scripts/make_catalog.py` from the digests a CI run reports.
- CI fails a build when Trivy finds a CRITICAL vulnerability with an available fix.

## Supported versions

Only the images whose digests are in the current `catalog.json` on `main` are supported.
