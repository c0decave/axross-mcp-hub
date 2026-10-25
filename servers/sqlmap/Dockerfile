# sqlmap + the FuzzingLabs sqlmap MCP server (patched, see PROVENANCE.md), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS fetch
# sqlmap 1.10.10 (the commit of its tag)
ARG SQLMAP_COMMIT=65b6e7b4acb13a736614a1ab73b0908476f3c24a
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
RUN git init -q /opt/sqlmap && cd /opt/sqlmap \
 && git remote add origin https://github.com/sqlmapproject/sqlmap.git \
 && git fetch -q --depth 1 origin "$SQLMAP_COMMIT" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$SQLMAP_COMMIT" \
 && rm -rf .git .github

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-sqlmap" \
      org.opencontainers.image.description="sqlmap 1.10.10 with the FuzzingLabs sqlmap MCP server (stdio)" \
      org.opencontainers.image.licenses="MIT AND GPL-2.0-or-later"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
      ca-certificates=20250419+deb13u1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# pip is removed from the venv and the venv tooling is purged: nothing installs Python packages at run time
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /opt/mcp/requirements.txt \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY --from=fetch /opt/sqlmap /opt/sqlmap
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-sqlmap/
# sqlmap's .py files are compiled now: the root file system is read-only at run time
RUN /opt/venv/bin/python -m compileall -q /opt/sqlmap \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && HOME=/tmp /opt/venv/bin/python /opt/sqlmap/sqlmap.py --version && rm -rf /tmp/.local
ENV HOME=/tmp \
    SQLMAP_PATH=/opt/sqlmap/sqlmap.py \
    SQLMAP_OUTPUT_DIR=/tmp/sqlmap-mcp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
