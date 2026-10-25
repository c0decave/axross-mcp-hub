# radare2 + r2mcp (the official radare2 MCP server, radareorg/radare2-mcp), MCP over stdio.
# Both are built from source at pinned commits; git checks every object against the commit ID.

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

FROM ${DEBIAN_IMAGE} AS build
# radare2 6.2.4 and radare2-mcp 1.9.0 (the commits their release tags point at)
ARG R2_COMMIT=485e5e205b190fc297a2a95a6f982ff5d9f54039
ARG R2MCP_COMMIT=562c0cf23c42b65b3052f0b294d8778c20facbde
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git build-essential meson ninja-build \
      pkg-config python3 patch \
 && rm -rf /var/lib/apt/lists/*
# fetch <url> <dir> <commit>: exactly that commit, or the build fails
RUN printf '%s\n' '#!/bin/sh' 'set -eu' 'git init -q "$2"' 'cd "$2"' \
      'git remote add origin "$1"' 'git fetch -q --depth 1 origin "$3"' 'git checkout -q FETCH_HEAD' \
      'test "$(git rev-parse HEAD)" = "$3"' > /usr/local/bin/fetch-commit \
 && chmod 0755 /usr/local/bin/fetch-commit
RUN fetch-commit https://github.com/radareorg/radare2.git /src/radare2 "$R2_COMMIT"
# radare2's meson subprojects (sdb, capstone, qjs, otezip, zydis) are fetched at the revisions
# pinned in its own subprojects/*.wrap files.
RUN cd /src/radare2 \
 && meson setup build --prefix=/opt/radare2 --libdir=lib --buildtype=release \
 && ninja -C build \
 && ninja -C build install
ENV PATH=/opt/radare2/bin:$PATH \
    PKG_CONFIG_PATH=/opt/radare2/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/radare2/lib
RUN fetch-commit https://github.com/radareorg/radare2-mcp.git /src/r2mcp "$R2MCP_COMMIT" \
 && cd /src/r2mcp \
 && ./configure --prefix=/opt/radare2 \
 && make -j"$(nproc)" \
 && install -m 0755 src/r2mcp /opt/radare2/bin/r2mcp \
 && r2 -v && /opt/radare2/bin/r2mcp -v

FROM ${DEBIAN_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/c0decave/axross-mcp-hub" \
      org.opencontainers.image.title="axross-mcp-radare2" \
      org.opencontainers.image.description="radare2 6.2.4 with the official r2mcp 1.9.0 MCP server (stdio)" \
      org.opencontainers.image.licenses="MIT AND LGPL-3.0-only"
COPY --from=build /opt/radare2 /opt/radare2
COPY LICENSES/ /usr/share/doc/axross-mcp-radare2/
RUN echo /opt/radare2/lib > /etc/ld.so.conf.d/radare2.conf && ldconfig \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin mcp \
 && mkdir -p /work \
 && /opt/radare2/bin/r2mcp -v
ENV HOME=/tmp \
    PATH=/opt/radare2/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 10001:10001
WORKDIR /work
# -s /work : open_file only accepts files under /work (the folder the user mounts)
# -g none  : radare2's own sandbox (cfg.sandbox) allows no exec, socket, network or disk writes
# no -r    : the raw run_command / run_javascript tools stay off
ENTRYPOINT ["/opt/radare2/bin/r2mcp", "-s", "/work", "-g", "none"]
