#!/usr/bin/env python3
"""The Bubblewrap form of a server image: its root file system as a tar.gz, and what runs it.

    scripts/rootfs.py --engine podman --image IMAGE@DIGEST --name NAME --out DIR

writes DIR/rootfs-NAME.tar.gz (the image's files, from `podman export` of a container that never ran, gzip
without a timestamp) and DIR/rootfs-NAME.json ({"name", "image", "url", "sha256", "size", "entrypoint", "user",
"workdir", "env"}: the image's ENTRYPOINT + CMD, its numeric USER, WORKDIR and ENV). sandbox-ai checks the
archive against "sha256" (signed in rootfs.json, see scripts/make_catalog.py and scripts/sign_catalog.py) and
runs "entrypoint" in it with bwrap, as that user, with only that environment. URL is where the build workflow
publishes the archive: a release of this repository named after the server and the archive's hash.
Standard library only.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys

RELEASES = "https://github.com/c0decave/axross-mcp-hub/releases/download"


def image_config(engine: str, image: str) -> dict:
    data = json.loads(subprocess.run([engine, "image", "inspect", image], check=True, capture_output=True,
                                     text=True).stdout)
    config = data[0].get("Config") or data[0].get("config") or {}
    return config


def run_facts(config: dict) -> dict:
    """entrypoint, user, workdir and env of an image config; a USER that is not numeric (or root) is refused."""
    entrypoint = list(config.get("Entrypoint") or []) + list(config.get("Cmd") or [])
    if not entrypoint or not entrypoint[0].startswith("/"):
        raise ValueError(f"the image's entrypoint {entrypoint!r} is not an absolute program")
    user = str(config.get("User") or "").split(":")[0]
    if not re.fullmatch(r"[0-9]{1,5}", user) or int(user) == 0:
        raise ValueError(f"the image's USER {config.get('User')!r} is not a numeric user other than root")
    env = {}
    for item in config.get("Env") or []:
        key, sep, value = item.partition("=")
        if sep and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key):
            env[key] = value
    return {"entrypoint": entrypoint, "user": int(user), "workdir": config.get("WorkingDir") or "/tmp", "env": env}


def export(engine: str, image: str, archive: str) -> None:
    container = subprocess.run([engine, "create", image], check=True, capture_output=True, text=True).stdout.strip()
    try:
        with open(archive, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as out:
            process = subprocess.Popen([engine, "export", container], stdout=subprocess.PIPE)
            for chunk in iter(lambda: process.stdout.read(1 << 20), b""):
                out.write(chunk)
            if process.wait() != 0:
                raise RuntimeError(f"{engine} export failed")
    finally:
        subprocess.run([engine, "rm", "-f", container], capture_output=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--engine", default="podman")
    parser.add_argument("--image", required=True, help="the image, by digest")
    parser.add_argument("--name", required=True)
    parser.add_argument("--out", default=".")
    opts = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", opts.name):
        parser.error("--name: 1-32 letters, digits, '-' or '_'")
    os.makedirs(opts.out, exist_ok=True)
    archive = os.path.join(opts.out, f"rootfs-{opts.name}.tar.gz")
    facts = run_facts(image_config(opts.engine, opts.image))
    export(opts.engine, opts.image, archive)
    with open(archive, "rb") as handle:
        data = handle.read()
    sha = hashlib.sha256(data).hexdigest()
    meta = {"name": opts.name, "image": opts.image, "url": f"{RELEASES}/rootfs-{opts.name}-{sha[:12]}/"
            f"rootfs-{opts.name}.tar.gz", "sha256": sha, "size": len(data), **facts}
    with open(os.path.join(opts.out, f"rootfs-{opts.name}.json"), "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2)
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
