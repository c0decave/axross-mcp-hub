# crtsh - provenance and audit

| | |
|---|---|
| MCP server | this repository, `src/server.py` (MIT, `LICENSES/axross-mcp-hub-MIT.txt`) |
| Service | https://crt.sh/ (Certificate Transparency search; JSON output and certificate download) |
| Python packages | `mcp==1.30.0` and its dependencies (httpx among them), hash-locked in `requirements.txt` |
| Debian packages | `ca-certificates=20250419+deb13u1` |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Why an own server

The whole logic is two HTTP requests. An own server keeps the request fixed to
`https://crt.sh/`, bounded, and working behind axross's allowlist proxy, with nothing else
to audit.

## Audit

**Tools:** `ct_search` (`GET https://crt.sh/?q=%.<domain>&output=json`, optionally
`exclude=expired`), `ct_certificate` (`GET https://crt.sh/?d=<id>`).

**Requests:** only `https://crt.sh/` with query parameters built by httpx (encoded); no
redirects are followed; answers are read as a stream and refused above 32 MiB; timeout
120 s. Anything other than HTTP 200 is an error.

**Arguments:** `domain` must be a domain name (`^(?=.{4,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z0-9-]{2,63}$`
after trimming and lower-casing: no scheme, path, wildcard or leading `-`/`.`);
`max_certificates` 1-5000; `certificate_id` 1-10^13.

**Network:** axross network **Allowlist with `crt.sh:443`**. axross then starts the container
with pasta forwarding only its proxy port and sets `HTTPS_PROXY`; httpx honours it
(`trust_env=True`), the TLS connection to crt.sh is end-to-end (CONNECT). Tested through
axross's own `core.mcp_egress.EgressProxy`: with `crt.sh:443` allowed the search answers;
with only `example.org:443` allowed it fails with `crt.sh not reachable: 403 Forbidden`.

**Files:** none. **Privacy:** passive - the domain itself is never contacted, but crt.sh
learns which domain was searched.
