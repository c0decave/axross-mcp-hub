#!/usr/bin/env python3
"""Which servers of a build workflow run may go into the catalog: the catalog job's choice.

    scripts/ci_results.py DIR [--out FILE]

DIR holds the per-server artifacts of the image jobs (``ci-<name>``, downloaded together): for every server of
``servers/`` this wants its ``result-<name>.json`` (written by the job's last step, so only when every required
step passed: build, the axross smoke runs, Trivy, push and the sandbox-ai Podman smoke), its
``digest-<name>.json`` and its passed sandbox-ai Podman report for exactly that image; when the job kept a
``rootfs-<name>.json`` (built from that digest; the job removes it when the rootfs or its Bubblewrap smoke
failed) also its passed Bubblewrap report for that rootfs; and its complete review, recorded in reviews.json
for exactly the files this run built from: scripts/sign_catalog.py's own checks, the ones it signs by. The
servers that pass are printed (and written to FILE, one per line) for ``make_catalog.py --ci-digests DIR --only
...``; every other server is named with its reasons (an annotation on GitHub Actions) and stays pending in
catalog.json and out of rootfs.json. Exit status 1 when no server passed (there is no catalog to make).
Standard library only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE_PREFIX = "ghcr.io/c0decave/axross-mcp-"


def _sign_catalog():
    spec = importlib.util.spec_from_file_location("sign_catalog_for_ci", Path(__file__).with_name("sign_catalog.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sign_catalog = _sign_catalog()


def _one(folder: Path, file_name: str) -> tuple[dict | None, str | None]:
    found = sorted(folder.rglob(file_name))
    if len(found) != 1:
        return None, f"{'no' if not found else len(found)} {file_name}"
    try:
        data = json.loads(found[0].read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"{file_name}: {exc}"
    return (data, None) if isinstance(data, dict) else (None, f"{file_name}: not an object")


def server_result(folder: Path, name: str, network: str | None, root: Path = ROOT) -> list[str]:
    """Why NAME (its entry's NETWORK) may not go into the catalog of this run (empty: it may)."""
    reviewed = [p.split(": ", 1)[1] if p.startswith(f"{name}: ") else p
                for p in sign_catalog.review_problems(root, name)]
    if reviewed:
        return reviewed
    result, problem = _one(folder, f"result-{name}.json")
    if problem or result.get("name") != name or result.get("passed") is not True:
        return ["its image job did not pass every step (see that job's annotations)"]
    digest, problem = _one(folder, f"digest-{name}.json")
    if problem:
        return [problem]
    image = f"{IMAGE_PREFIX}{name}"
    if digest.get("name") != name or digest.get("image") != image or not isinstance(digest.get("digest"), str):
        return [f"digest-{name}.json is not of {image}"]
    pinned = f"{image}@{digest['digest']}"
    sha256 = None  # no rootfs kept: Podman alone
    if any(folder.rglob(f"rootfs-{name}.json")):
        rootfs, problem = _one(folder, f"rootfs-{name}.json")
        if problem:
            return [problem]
        if rootfs.get("name") != name or rootfs.get("image") != pinned:
            return [f"rootfs-{name}.json is not built from {pinned}"]
        sha256 = str(rootfs.get("sha256"))
    return [p.split(": ", 1)[1] if p.startswith(f"{name}: ") else p
            for p in sign_catalog.server_problems(folder, name, pinned, sha256, network)]


def annotate(level: str, title: str, message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        title = title.replace("%", "%25").replace(":", "%3A").replace(",", "%2C")
        print(f"::{level} title={title}::{message}", flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("folder", type=Path, help="the downloaded ci-<name> artifacts")
    parser.add_argument("--root", type=Path, default=ROOT, help="the repository (its servers/)")
    parser.add_argument("--out", type=Path, help="write the names that passed here, one per line")
    opts = parser.parse_args(argv)
    networks = {p.parent.name: json.loads(p.read_text(encoding="utf-8")).get("network")
                for p in sorted((opts.root / "servers").glob("*/server.json"))}
    passed, summary = [], ["| server | catalog | why |", "|---|---|---|"]
    for name, network in networks.items():
        problems = (server_result(opts.folder, name, network, opts.root) if opts.folder.is_dir()
                    else [f"{opts.folder}: no folder"])
        if problems:
            print(f"left out: {name}: " + "; ".join(problems), file=sys.stderr)
            annotate("error", f"left out of the catalog ({name})", "\n".join(problems))
            summary.append(f"| {name} | left out | {'; '.join(problems)} |")
            continue
        passed.append(name)
        notes = []
        if not any(opts.folder.rglob(f"rootfs-{name}.json")):
            notes.append("Podman only (its rootfs or its Bubblewrap smoke failed: no rootfs)")
        for note in notes:
            annotate("warning", f"in the catalog with a caveat ({name})", note)
        summary.append(f"| {name} | in | {'; '.join(notes) or 'Podman and Bubblewrap passed'} |")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write("### Servers of this run\n\n" + "\n".join(summary) + "\n\n")
    if opts.out:
        opts.out.write_text("".join(f"{name}\n" for name in passed), encoding="utf-8")
    print("\n".join(passed))
    if not passed:
        print("no server passed: no catalog", file=sys.stderr)
        annotate("error", "no catalog", "no server passed its smoke runs; see the image jobs")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
