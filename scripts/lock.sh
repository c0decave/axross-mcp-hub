#!/bin/sh
# Re-lock servers/*/requirements.txt from servers/*/requirements.in: hash-pinned, for
# Python 3.13 on every platform. uv runs in a disposable container, never on the host.
#   scripts/lock.sh            (from the repository root; needs podman)
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
# python:3.13-slim-trixie, by the digest of its image index
image=docker.io/library/python@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962
exec podman run --rm --cap-drop=ALL --security-opt=no-new-privileges --userns=keep-id \
  -e HOME=/tmp -v "$root/servers:/servers:rw" "$image" sh -euc '
    export PATH=$HOME/.local/bin:$PATH
    pip install -q --no-cache-dir --disable-pip-version-check uv==0.9.5
    for d in /servers/*/; do
      [ -f "$d/requirements.in" ] || continue
      echo "== $d"
      uv pip compile -q --no-cache --generate-hashes --universal --python-version 3.13 \
        --custom-compile-command "scripts/lock.sh" -o "$d/requirements.txt" "$d/requirements.in"
    done'
