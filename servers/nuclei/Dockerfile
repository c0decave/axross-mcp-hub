# ProjectDiscovery nuclei + the FuzzingLabs nuclei MCP server (patched, see PROVENANCE.md), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS fetch
ARG TARGETARCH
ARG NUCLEI_VERSION=3.11.1
# sha256 from the release's nuclei_3.11.1_checksums.txt
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
# nuclei-templates v10.5.1
ARG TEMPLATES_COMMIT=79fb682760ab3d5b0e22afbb44709353cbebf023
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git unzip \
 && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH:-amd64}" in \
      amd64) sum="$NUCLEI_SHA256_AMD64" ;; arm64) sum="$NUCLEI_SHA256_ARM64" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; esac \
 && curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH:-amd64}.zip" \
 && echo "$sum  /tmp/nuclei.zip" | sha256sum -c - \
 && unzip -q /tmp/nuclei.zip nuclei LICENSE.md -d /opt/nuclei \
 && chmod 0755 /opt/nuclei/nuclei
RUN git init -q /opt/nuclei-templates && cd /opt/nuclei-templates \
 && git remote add origin https://github.com/projectdiscovery/nuclei-templates.git \
 && git fetch -q --depth 1 origin "$TEMPLATES_COMMIT" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$TEMPLATES_COMMIT" \
 && rm -rf .git .github

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-nuclei" \
      org.opencontainers.image.description="nuclei 3.11.1 with nuclei-templates 10.5.1 and the FuzzingLabs nuclei MCP server (stdio)" \
      org.opencontainers.image.licenses="MIT"
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
COPY --from=fetch /opt/nuclei/nuclei /usr/local/bin/nuclei
COPY --from=fetch /opt/nuclei/LICENSE.md /usr/share/doc/nuclei/LICENSE.md
COPY --from=fetch /opt/nuclei-templates /opt/nuclei-templates
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-nuclei/
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && HOME=/tmp nuclei -version -disable-update-check 2>&1 | tail -1 && rm -rf /tmp/.config /tmp/.cache
ENV HOME=/tmp \
    NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates \
    NUCLEI_OUTPUT_DIR=/tmp/nuclei-mcp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
