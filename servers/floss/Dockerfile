# Mandiant FLOSS + an MCP server of this hub (src/server.py), MCP over stdio.
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
FROM ${DEBIAN_IMAGE} AS wheel
# Two FLOSS dependencies publish no usable wheel: binary2strings (MIT, C++; Linux sdist only)
# and halo (MIT, its wheel is Python 2 only). pip wheel fetches every pinned file and checks
# it against the hashes of requirements.txt, takes the wheels as they are and builds the two
# sdists here - with hash-pinned build dependencies and no build isolation, so nothing
# unpinned is downloaded. (binary2strings' setup.py only compiles src/*.cpp.)
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
      python3-dev=3.13.5-1 g++ \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-build.txt /build/
RUN python3 -m venv /build/venv \
 && /build/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes \
      --only-binary=:all: -r /build/requirements-build.txt \
 && /build/venv/bin/pip wheel --no-cache-dir --disable-pip-version-check --require-hashes \
      --no-deps --no-build-isolation -r /build/requirements.txt -w /wheels \
 && ls /wheels

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-floss" \
      org.opencontainers.image.description="Mandiant FLOSS 3.2.0 behind an MCP server of axross-mcp-hub: obfuscated strings (stdio)" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0"
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3=3.13.5-1 python3-venv=3.13.5-1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/mcp/requirements.txt
# the wheels checked or built above (bind-mounted, not copied), offline; pip is removed from
# the venv and the venv tooling is purged afterwards
RUN --mount=type=bind,from=wheel,source=/wheels,target=/opt/wheels \
    python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --no-index --no-deps \
      /opt/wheels/*.whl \
 && /opt/venv/bin/python -m pip uninstall -y -q pip \
 && apt-get purge -y -q python3-venv python3.13-venv python3-pip-whl python3-setuptools-whl \
 && rm -rf /var/cache/apt /var/log/apt /var/log/dpkg.log
COPY src/server.py /opt/mcp/server.py
COPY LICENSES/ /usr/share/doc/axross-mcp-floss/
RUN /opt/venv/bin/python -m compileall -q /opt/mcp \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work \
 && HOME=/tmp /opt/venv/bin/floss --version && rm -rf /tmp/.cache /tmp/.config
ENV HOME=/tmp \
    PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"]
