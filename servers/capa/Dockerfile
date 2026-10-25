# Mandiant capa + the FuzzingLabs capa MCP server (patched, see PROVENANCE.md), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS data
# capa-rules v10.0.0 and the FLIRT signatures of capa v10.0.0, at the commits of those tags
ARG CAPA_RULES_COMMIT=805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5
ARG CAPA_COMMIT=85813ebc5b99ccdbe43147e46796d0bd6700f30a
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
RUN printf '%s\n' '#!/bin/sh' 'set -eu' 'git init -q "$2"' 'cd "$2"' \
      'git remote add origin "$1"' 'git fetch -q --depth 1 origin "$3"' 'git checkout -q FETCH_HEAD' \
      'test "$(git rev-parse HEAD)" = "$3"' 'rm -rf .git' > /usr/local/bin/fetch-commit \
 && chmod 0755 /usr/local/bin/fetch-commit \
 && fetch-commit https://github.com/mandiant/capa-rules.git /opt/capa/rules "$CAPA_RULES_COMMIT" \
 && fetch-commit https://github.com/mandiant/capa.git /src/capa "$CAPA_COMMIT" \
 && cp -r /src/capa/sigs /opt/capa/sigs && cp /src/capa/LICENSE.txt /opt/capa/LICENSE.txt

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-capa" \
      org.opencontainers.image.description="Mandiant capa 10.0.0 with capa-rules 10.0.0 and the FuzzingLabs capa MCP server (stdio)" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# pip is removed from the venv and the venv tooling is purged: nothing installs Python packages at run time
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /opt/mcp/requirements.txt \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY --from=data /opt/capa /opt/capa
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-capa/
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work \
 && /opt/venv/bin/capa --version
ENV HOME=/tmp \
    PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CAPA_RULES_DIR=/opt/capa/rules \
    CAPA_SIGS_DIR=/opt/capa/sigs \
    CAPA_OUTPUT_DIR=/tmp/capa-mcp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
