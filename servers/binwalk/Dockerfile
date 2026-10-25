# binwalk + the FuzzingLabs binwalk MCP server (patched, see PROVENANCE.md), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-binwalk" \
      org.opencontainers.image.description="binwalk 2.4.3 with the FuzzingLabs binwalk MCP server (stdio)" \
      org.opencontainers.image.licenses="MIT"
# binwalk plus the extractors it calls for common firmware formats
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
      binwalk=2.4.3+dfsg1-2+deb13u1 xxd=2:9.1.1230-2 \
      7zip=25.01+dfsg-1~deb13u2 squashfs-tools=1:4.6.1-1 cpio=2.15+dfsg-2 unzip=6.0-29+deb13u1 \
      lzop=1.04-2 xz-utils=5.8.1-1+deb13u2 bzip2=1.0.8-6 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# pip is removed from the venv and the venv tooling is purged: nothing installs Python packages at run time
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /opt/mcp/requirements.txt \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-binwalk/
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work /out \
 && binwalk --help | head -2
ENV HOME=/tmp \
    BINWALK_OUTPUT_DIR=/tmp/binwalk-mcp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
