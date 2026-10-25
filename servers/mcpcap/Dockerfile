# mcpcap (PCAP analysis MCP server, mcpcap/mcpcap) at a pinned commit, MCP over stdio. Unpatched.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS fetch
# mcpcap v0.10.0 (the commit of its tag)
ARG MCPCAP_COMMIT=0b7af6b29f25dd09b949c50f7a69bc493b84c2bf
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
RUN git init -q /src && cd /src \
 && git remote add origin https://github.com/mcpcap/mcpcap.git \
 && git fetch -q --depth 1 origin "$MCPCAP_COMMIT" && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$MCPCAP_COMMIT" \
 && mkdir -p /opt/mcpcap/src && cp -r src/mcpcap /opt/mcpcap/src/ && cp LICENSE /opt/mcpcap/ \
 && printf 'version = "0.10.0"\n__version__ = version\n' > /opt/mcpcap/src/mcpcap/_version.py

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-mcpcap" \
      org.opencontainers.image.description="mcpcap 0.10.0: DNS, DHCP, ICMP, TCP, SIP and capinfos analysis of PCAP files (stdio)" \
      org.opencontainers.image.licenses="MIT AND GPL-2.0-only"
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
COPY --from=fetch /opt/mcpcap /opt/mcpcap
COPY LICENSES/ /usr/share/doc/axross-mcp-mcpcap/
RUN echo /opt/mcpcap/src > "$(/opt/venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/mcpcap.pth" \
 && /opt/venv/bin/python -m compileall -q /opt/mcpcap/src \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work \
 && HOME=/tmp /opt/venv/bin/python -I -c 'import mcpcap; print("mcpcap", mcpcap.__version__)' && rm -rf /tmp/.config /tmp/.cache
ENV HOME=/tmp
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "-m", "mcpcap.cli"]
