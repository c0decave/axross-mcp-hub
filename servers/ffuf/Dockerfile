# ffuf + the FuzzingLabs ffuf MCP server (patched, see PROVENANCE.md), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS fetch
# SecLists (MIT) at a pinned commit: five wordlists, each checked against its sha256
ARG SECLISTS_COMMIT=ab068333d7d44a9376e2037b0ed7d2e8ca5c6610
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/wordlists && cd /opt/wordlists \
 && base="https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}" \
 && curl -fsSL -o common.txt "$base/Discovery/Web-Content/common.txt" \
 && curl -fsSL -o raft-small-directories.txt "$base/Discovery/Web-Content/raft-small-directories.txt" \
 && curl -fsSL -o raft-small-files.txt "$base/Discovery/Web-Content/raft-small-files.txt" \
 && curl -fsSL -o burp-parameter-names.txt "$base/Discovery/Web-Content/burp-parameter-names.txt" \
 && curl -fsSL -o subdomains-top1million-5000.txt "$base/Discovery/DNS/subdomains-top1million-5000.txt" \
 && printf '%s\n' \
      "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a  common.txt" \
      "06e1ac7b390c17eb9e0da416d0599c785a1541813daa95b01c676bc92d55185f  raft-small-directories.txt" \
      "226eaa23b54107ba5eb4c0c0bc415b6c8ce7289109b05591908d695757c019a2  raft-small-files.txt" \
      "91f7e457415ffd0e4278d13887804036b62240a135a022a6fd6e831a7151899f  burp-parameter-names.txt" \
      "e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19  subdomains-top1million-5000.txt" \
    | sha256sum -c -

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-ffuf" \
      org.opencontainers.image.description="ffuf 2.1.0 with SecLists wordlists and the FuzzingLabs ffuf MCP server (stdio)" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
      ffuf=2.1.0-1+b9 ca-certificates=20250419+deb13u1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# pip is removed from the venv and the venv tooling is purged: nothing installs Python packages at run time
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /opt/mcp/requirements.txt \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY --from=fetch /opt/wordlists /opt/wordlists
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-ffuf/
RUN /opt/venv/bin/python -m compileall -q /opt/mcp \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work \
 && ffuf -V
ENV HOME=/tmp \
    FFUF_OUTPUT_DIR=/tmp/ffuf-mcp \
    FFUF_WORDLISTS_DIR=/opt/wordlists
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
