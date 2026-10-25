# gitleaks + an MCP server of this hub (src/server.py), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

# gitleaks 8.30.1 built from the commit of its tag with a current Go toolchain: the release
# binary was built with Go 1.24.11, whose standard library has a CRITICAL fixed vulnerability
# (CVE-2025-68121), and Go 1.25.14 still has HIGH ones fixed only in 1.26/1.27. Modules come
# from the module proxy, verified against go.sum.
FROM docker.io/library/golang:1.27-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
RUN git init -q /src && cd /src \
 && git remote add origin https://github.com/gitleaks/gitleaks.git \
 && git fetch -q --depth 1 origin "$GITLEAKS_COMMIT" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$GITLEAKS_COMMIT"
# Dependencies of gitleaks 8.30.1 with fixed HIGH vulnerabilities are raised to the fixed
# versions (klauspost/compress CVE-2026-63209; golang.org/x/crypto CVE-2025-47913,
# CVE-2026-39828..39830, CVE-2026-56854; golang.org/x/text CVE-2026-56851, CVE-2026-56852);
# the new go.sum lines are checked against sum.golang.org.
RUN cd /src && go mod verify \
 && go get github.com/klauspost/compress@v1.18.7 golang.org/x/crypto@v0.55.0 golang.org/x/text@v0.41.0 \
 && go mod verify \
 && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=v8.30.1" \
      -o /opt/gitleaks/gitleaks . \
 && cp LICENSE config/gitleaks.toml /opt/gitleaks/ \
 && /opt/gitleaks/gitleaks version && go version

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-gitleaks" \
      org.opencontainers.image.description="gitleaks 8.30.1 (built with Go 1.27) behind an MCP server of axross-mcp-hub: secrets in files and git history (stdio)" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
      git=1:2.47.3-0+deb13u1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# pip is removed from the venv and the venv tooling is purged: nothing installs Python packages at run time
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /opt/mcp/requirements.txt \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY --from=build /opt/gitleaks /opt/gitleaks
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-gitleaks/
RUN ln -s /opt/gitleaks/gitleaks /usr/local/bin/gitleaks \
 && /opt/venv/bin/python -m compileall -q /opt/mcp \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work \
 && gitleaks version
ENV HOME=/tmp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
