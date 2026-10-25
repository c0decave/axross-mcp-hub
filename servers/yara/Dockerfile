# YARA + the FuzzingLabs YARA MCP server (patched, see PROVENANCE.md), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS rules
# Yara-Rules/rules (GPL-2.0) at a pinned commit: the generic crypto, packer,
# anti-debug/anti-VM and capability rules. Only files that compile with this YARA
# (and with each other) go into index.yar.
ARG YARA_RULES_COMMIT=0f93570194a80d2f2032869055808b0ddcdfb360
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git yara=4.5.2-1 \
 && rm -rf /var/lib/apt/lists/*
RUN git init -q /src && cd /src \
 && git remote add origin https://github.com/Yara-Rules/rules.git \
 && git fetch -q --depth 1 origin "$YARA_RULES_COMMIT" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$YARA_RULES_COMMIT"
RUN mkdir -p /opt/yara/rules \
 && cd /src && cp -r crypto packers antidebug_antivm capabilities LICENSE /opt/yara/rules/ \
 && cd /opt/yara/rules && : > index.yar \
 && for f in $(find crypto packers antidebug_antivm capabilities -name '*.yar' | sort); do \
      cp index.yar index.try && echo "include \"/opt/yara/rules/$f\"" >> index.try; \
      if yara -w index.try /dev/null >/dev/null 2>&1; then mv index.try index.yar; \
      else echo "skipped (does not compile): $f"; rm -f index.try; fi; \
    done \
 && echo "rules in index.yar: $(grep -c include index.yar)" \
 && yara -w index.yar /dev/null

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-yara" \
      org.opencontainers.image.description="YARA 4.5.2 with the FuzzingLabs YARA MCP server and a Yara-Rules subset (stdio)" \
      org.opencontainers.image.licenses="MIT AND BSD-3-Clause AND GPL-2.0-only"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 yara=4.5.2-1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# pip is removed from the venv and the venv tooling is purged: nothing installs Python packages at run time
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /opt/mcp/requirements.txt \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY --from=rules /opt/yara/rules /opt/yara/rules
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-yara/
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work /rules \
 && yara --version
ENV HOME=/tmp \
    YARA_RULES_DIR=/opt/yara/rules \
    YARA_OUTPUT_DIR=/tmp/yara-mcp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
