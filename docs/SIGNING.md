# Signing the catalog for sandbox-ai

axross reads `catalog.json` as it is (digests pinned, no signature). sandbox-ai reads the same file
(`https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json`, its servers named `hub:NAME`)
and its `mcp add` takes an entry only from a catalog with a valid signature:

```
sandbox-mcp: yara: its catalog is not signed by a trusted key (https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json.sig cannot be read) ... --unsigned adds it anyway
```

The signature (`ssh-keygen -Y sign`, namespace `sandbox-ai-mcp`, principal `mcp@sandbox-ai`, the same key that
signs [sandbox-ai-mcp](https://github.com/c0decave/sandbox-ai-mcp)) says that every published server of the
catalog

- was **reviewed completely by us** - its shipped MCP server code read for backdoors and bad code, the review
  recorded in its `servers/NAME/PROVENANCE.md` and in `reviews.json`, for exactly the files the image is built
  from;
- was built from its pinned sources and **passed its smoke spec with sandbox-ai's own run line** under Podman
  (and under Bubblewrap where `rootfs.json` offers that form), for exactly the image digest and rootfs hash the
  catalog pins.

sandbox-ai checks it against its file `sandbox/mcp-signers`. A server that does not meet both stays **pending**
in the signed catalog (no digest): neither sandbox-ai nor axross offers it until a later run vouches for it.

## What sandbox-ai reads

From the top of branch `main`:

| file | what for |
|---|---|
| `catalog.json` | the entries, each image pinned by digest (axross reads it too) |
| `catalog.json.sig` | the signature over `catalog.json`; without it sandbox-ai refuses every entry (unless `--unsigned`) |
| `rootfs.json` | the Bubblewrap form of each server: archive URL (a release asset), SHA-256, entrypoint, user |
| `rootfs.json.sig` | its signature; a signed catalog takes only a signed `rootfs.json` (otherwise Podman only) |

`scripts/sign_catalog.py` writes both `.sig` files next to their files at the top of the repository, which is
where raw.githubusercontent.com serves them from (`tests/test_sign_catalog.py` checks this with sandbox-ai's own
code when `SANDBOX_AI_CHECKOUT` names a sandbox-ai checkout).

## The review: `reviews.json`

Only MCP servers whose shipped code we reviewed completely ourselves are signed. `reviews.json` says, for every
server of `servers/`:

- `"reviewed": true` - the record (`PROVENANCE.md`), what MCP code ships (`mcp_code`) and `files`: the SHA-256 of
  everything that decides what the image ships (`Dockerfile`: base and pinned upstream commits and packages;
  `requirements*.txt`: the hash-locked Python packages; `src/`: the MCP server). A server whose files changed
  since its review is neither taken into a CI catalog nor signed. After reviewing the change (and updating its
  `PROVENANCE.md`), record it:

  ```bash
  python3 scripts/sign_catalog.py --record-review NAME
  ```

- `"reviewed": false` - with `missing`: what a complete review still needs. Such a server is never signed. To
  publish it, review its whole shipped code, write the record (file by file, the findings, how each is handled,
  that no backdoor was found), then set `"reviewed": true` with its record in the same commit and run
  `--record-review NAME`. `--record-review` never marks a server reviewed on its own.

Not reviewed completely at the moment: **mcpcap** and **radare2** (see `reviews.json` and the README).

## What the CI run produces

`.github/workflows/build.yml`, per server of `servers/`: build, start and smoke spec with axross's run line
(unchanged), Trivy, push to `ghcr.io/c0decave/axross-mcp-NAME`, then with a checkout of sandbox-ai
(`SANDBOX_AI_REF`):

- `smoke-NAME-sandbox-ai-podman.json` (required): the pushed `IMAGE@DIGEST`, pulled by digest, started with
  sandbox-ai's own `podman run` line (`mcp.image_command`) by `scripts/axross_smoke.py --runner
  sandbox-ai-podman`: the server's spec of `tests/axross-smoke.json` - its files in the mounted folders, its
  local target, `tools/list` compared with `servers/NAME/tools.json`, the real call and the refused call;
- `rootfs-NAME.tar.gz` and `rootfs-NAME.json` from that very image (`scripts/rootfs.py`) and
  `smoke-NAME-sandbox-ai-bwrap.json`: the archive checked, unpacked and run with sandbox-ai's Bubblewrap runner
  (`mcp_rootfs`), with its `rootfs_sha256` (optional: when either fails, the job leaves the rootfs out and the
  server is published for Podman alone);
- on `main`: the archive published as the release `rootfs-NAME-<first 12 hex digits of its SHA-256>`.

sandbox-ai has no egress allowlist for image servers: it grants an allowlist entry (crtsh) the full network, and
that is how its smoke runs - crtsh's live call to crt.sh runs here (axross's own run skips it in CI). A failed
real call is repeated twice (`--call-retries 2`, a public service fails now and then); a refusal must come at
the first try.

Each image job uploads what it has as the artifact `ci-NAME`, also when a step failed, with
`result-NAME.json` only when every required step passed.

The `catalog` job (only for `main`, also when some image jobs failed, not when the tests failed or the run was
cancelled): `scripts/ci_results.py` takes the servers whose job passed, whose reports `sign_catalog.py` would
take (for the digest and rootfs that job pushed) and whose review is recorded for the files of this run; every
other server is named in an annotation and left pending (`make_catalog.py --only ...`: no digest in
`catalog.json`, nothing in `rootfs.json`). It writes `catalog.json`, `rootfs.json` and `digests.json` and
uploads them with all smoke reports as the artifact `catalog` (reports in its folder `ci-digests/`) and as the
pre-release `ci-catalog-RUN` (the reports as `ci-digests.tar.gz`; only the newest run's is kept), which is
reachable where the artifact storage is not.

## What `sign_catalog.py` checks

It refuses unless `catalog.json` and `rootfs.json` are what `servers/*/server.json` and `digests.json` give
(`make_catalog.py --check`) and every entry with a digest

- is reviewed (`reviews.json`, its record there, its shipped files unchanged since the review);
- has its passed `sandbox-ai-podman` report, and its passed `sandbox-ai-bwrap` report when `rootfs.json` has a
  rootfs for it, of the right runner, for the pinned `IMAGE@DIGEST` (and the `rootfs.json` SHA-256), with
  `tools.json` matched, the real call answered and the refused call refused - one report per server and runner
  under the folder (one CI run only);
- was run with no more network than its entry declares (an entry with `network: none` is never vouched for by a
  run that had a network; `allowlist` counts as `full`, which is what sandbox-ai gives it);

and `rootfs.json` pins no rootfs for a server the catalog does not publish.

Before signing it is worth reading the catalog with sandbox-ai's own code (no pull, no fetch):

```bash
python3 scripts/make_catalog.py --check --allow-pending --sandbox-ai "$SANDBOX_AI"
```

## Before the first run

- The smoke runs check out `github.com/c0decave/sandbox-ai` at `SANDBOX_AI_REF` (repository variable, default
  `main`); it must contain `sandbox/mcp.py`, `sandbox/mcp_rootfs.py`, `sandbox/mcp-signers` and
  `sandbox/release_keys.py`, else the job stops naming the file:
  `gh variable set SANDBOX_AI_REF -R c0decave/axross-mcp-hub --body vX.Y.Z`.
- `sandbox/mcp-signers` of the published sandbox-ai carries the signing key's `.pub` (it does: the same key
  signs sandbox-ai-mcp).
- The packages `ghcr.io/c0decave/axross-mcp-*` must be public (github.com/c0decave?tab=packages, package
  settings, "Change visibility"): sandbox-ai and axross pull them without a login. The workflow logs podman in
  with the job's token, so CI does not depend on it.

## The steps

Run them from a checkout of the repository. `KEY` is the signing key, `SANDBOX_AI` a sandbox-ai checkout whose
`sandbox/mcp-signers` has its public key.

```bash
KEY=/path/to/mcp-signing-key
SANDBOX_AI=../sandbox-ai
ME=(-c user.name=dash -c user.email=c0decave@users.noreply.github.com)

# 1. Push main (a CI run of main starts; the commit of a signed catalog starts none).
git push origin main

# 2. Wait for it (if none started: gh workflow run build.yml -R c0decave/axross-mcp-hub --ref main).
RUN=$(gh run list -R c0decave/axross-mcp-hub --workflow build.yml --branch main -L 1 --json databaseId -q '.[0].databaseId')
gh run watch "$RUN" -R c0decave/axross-mcp-hub --exit-status   # image jobs may fail: see the catalog job

# 3. Its catalog, rootfs.json, digests.json and the smoke reports (the pre-release of that run).
CI=$(mktemp -d)
gh release download "ci-catalog-$RUN" -R c0decave/axross-mcp-hub -D "$CI"
tar -xzf "$CI/ci-digests.tar.gz" -C "$CI"
#    (or: gh run download "$RUN" -R c0decave/axross-mcp-hub -n catalog -D "$CI")
cp "$CI/catalog.json" "$CI/rootfs.json" "$CI/digests.json" .

# 4. Read it with sandbox-ai's code, sign (refuses unless every published server is reviewed and passed), verify.
python3 scripts/make_catalog.py --check --allow-pending --sandbox-ai "$SANDBOX_AI"
python3 scripts/sign_catalog.py --key "$KEY" --reports "$CI/ci-digests"
python3 scripts/sign_catalog.py --verify --signers "$SANDBOX_AI/sandbox/mcp-signers"

# 5. Commit and publish (this commit starts no rebuild: the workflow ignores these files).
git add catalog.json rootfs.json digests.json catalog.json.sig rootfs.json.sig
git "${ME[@]}" commit -m "Catalog of CI run $RUN, signed"
sandbox-ai privacy-check .
git push origin main
```

Check what users get:

```bash
curl -fsS https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json.sig | head -1   # -----BEGIN SSH SIGNATURE-----
sandbox-ai mcp catalog          # the entries of "hub" say "signed"
```

Every later release goes the same way: merge into main, push (a CI run), then steps 2 to 5 with that run's
pre-release. Note that the signed catalog replaces the digests of every server: one left pending by a run (not
reviewed, or its job failed) is offered to neither sandbox-ai nor axross until a later run passes it.
