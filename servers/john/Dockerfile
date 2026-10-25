# John the Ripper (jumbo) + an MCP server of this hub (src/server.py), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS build
# openwall/john bleeding-jumbo at a pinned commit (jumbo has no release newer than 2019)
ARG JOHN_COMMIT=5184bc0b8c105f8c5978b112e723d65b2de3e63e
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git build-essential pkg-config \
      libssl-dev zlib1g-dev libgmp-dev libbz2-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git init -q /src && cd /src \
 && git remote add origin https://github.com/openwall/john.git \
 && git fetch -q --depth 1 origin "$JOHN_COMMIT" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$JOHN_COMMIT"
# --disable-native-tests: a portable build (no -march=native of the build host)
RUN cd /src/src \
 && ./configure --disable-native-tests --disable-opencl \
 && make -s clean && make -sj"$(nproc)" \
 && mkdir -p /opt/john && cp -a /src/run /opt/john/run && cp /src/doc/LICENSE /opt/john/LICENSE \
 && /opt/john/run/john --list=build-info | head -5

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-john" \
      org.opencontainers.image.description="John the Ripper (bleeding-jumbo 5184bc0, CPU) behind an MCP server of axross-mcp-hub (stdio)" \
      org.opencontainers.image.licenses="MIT AND GPL-2.0-or-later"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
      libssl3t64 zlib1g libgmp10 libbz2-1.0 libgomp1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# pip is removed from the venv and the venv tooling is purged: nothing installs Python packages at run time
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /opt/mcp/requirements.txt \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY --from=build /opt/john /opt/john
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-john/
RUN /opt/venv/bin/python -m compileall -q /opt/mcp \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work \
 && HOME=/tmp /opt/john/run/john --list=build-info | head -2 && rm -rf /tmp/.john
ENV HOME=/tmp \
    OMP_NUM_THREADS=4
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
