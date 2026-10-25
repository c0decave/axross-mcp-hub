# gitleaks - provenance and audit

| | |
|---|---|
| MCP server | this repository, `src/server.py` (MIT, `LICENSES/axross-mcp-hub-MIT.txt`) |
| Tool | gitleaks 8.30.1, https://github.com/gitleaks/gitleaks, built from commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` (tag v8.30.1) |
| Tool licence | MIT (`LICENSES/gitleaks-MIT.txt`) |
| Build | `docker.io/library/golang:1.27-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4` (Go 1.27.3), `go mod verify`, `CGO_ENABLED=0` |
| Other packages | git, Debian trixie `git=1:2.47.3-0+deb13u1` (GPL-2.0, `LICENSES/debian-git-copyright.txt`); `mcp==1.30.0` and its dependencies, hash-locked in `requirements.txt` |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Why an own server and a source build

The only gitleaks entry found in the MCP registry results
(`io.github.AnshumanAtrey/gitleaks-github-secret-scanner`, "Gitleaks Cloud - GitHub API Key
Hunter & Secret Scanner") is a remote service without a package - a different job.
gitleaks' CLI is small, so the server maps its `dir` and `git` modes to two tools.

The gitleaks 8.30.1 release binary was built with Go 1.24.11; Trivy reports a CRITICAL
vulnerability with a fix in that Go standard library (CVE-2025-68121). gitleaks is therefore
built here from the tag's commit with Go 1.27.3. Go 1.25.14 was tried first and still had
HIGH standard-library vulnerabilities fixed only in 1.26/1.27. gitleaks' own dependencies
had fixed HIGH vulnerabilities too, so they are raised in the build with `go get`
(`github.com/klauspost/compress` v1.17.11 -> v1.18.7, `golang.org/x/crypto` v0.35.0 ->
v0.55.0, `golang.org/x/text` v0.22.0 -> v0.41.0; `go get` raised `x/sync` and `x/sys` with
them); the new go.sum lines are checked against sum.golang.org. Result: Trivy reports no
fixable CRITICAL or HIGH vulnerability in the image.

## Audit

**Tools:** `scan_directory` (gitleaks dir), `scan_git_history` (gitleaks git), `list_rules`
(rule IDs of the built-in `config/gitleaks.toml`).

**Command execution:** gitleaks runs with an argument list, no shell, a timeout (1-3600 s),
`--exit-code 0`, `--no-banner --no-color --log-level error`, and its JSON report goes to a
private temporary folder that is removed after reading.

**Arguments:** `path` / `repository` must resolve under `/work` (passed absolute; a
repository must contain `.git`); `config` must be a `.toml` file under `/work`;
`max_findings` 1-5000, `max_file_mb` 1-500.

**Secrets in answers:** `--redact` is on unless the caller sets `redact: false`.

**git configuration of the scanned repository:** `gitleaks git` runs `git log -p`, and a
mounted repository's own `.git/config` / `.gitattributes` can make git run programs - a
`diff.<driver>.textconv` command, an external diff, `core.fsmonitor`, hooks. Reproduced:
in a repository with `*.txt diff=evil` and `diff.evil.textconv = sh -c '...'`, plain
`git log -p` runs the command, and a plain `gitleaks git` reports the token that the
textconv program printed (2 findings), i.e. it executed it. **Fixed:** the history scan
passes `--log-opts=--full-history --all --no-textconv --no-ext-diff`, and every git call
gets `GIT_CONFIG_NOSYSTEM=1` plus `GIT_CONFIG_COUNT` entries `safe.directory=*`,
`core.fsmonitor=false`, `core.hooksPath=/dev/null`, `diff.external=` (empty). The same
malicious repository then gives 0 findings and the command does not run.
`safe.directory=*` is needed because a mounted repository belongs to another user; it does
not enable anything else.

**Network:** none. **Files:** read only.
