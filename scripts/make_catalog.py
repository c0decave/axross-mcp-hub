#!/usr/bin/env python3
"""Write catalog.json - an axross MCP catalog - from the servers' metadata and image digests.

Each ``servers/<name>/server.json`` is one catalog entry without its digest. The digests
come from ``digests.json`` (``{"images": {"<name>": "sha256:..." | null}}``), which the
digests of a CI run update (``--ci-digests``: the ``digest-<name>.json`` files the build
workflow uploads, or a folder of them). Image references in the catalog are always
``image`` + ``digest``; an entry whose image has no digest yet is written *without* one,
the catalog says ``"state": "pending-digests"``, and axross refuses that entry
("digest: sha256:<64 hex digits> (an image is pinned)") - no digest is ever invented.

    scripts/make_catalog.py                       # write catalog.json from digests.json
    scripts/make_catalog.py --ci-digests DIR --write-digests   # take a CI run's digests
    scripts/make_catalog.py --check               # catalog.json up to date and pinned?
    scripts/make_catalog.py --check --allow-pending --axross /path/to/axross

``--check`` exits 1 when catalog.json is not what the metadata and digests give, when an
entry is invalid, or when digests are pending (unless ``--allow-pending``). With
``--axross DIR`` it also loads the catalog with axross's own validator
(``core.mcp_catalog``, run it with axross's Python) and requires every pinned entry to be
accepted unchanged and every pending entry to be refused for its missing digest.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "axross-mcp-catalog"
VERSION = 1
IMAGE_PREFIX = "ghcr.io/c0decave/axross-mcp-"
TITLE = "axross-mcp-hub"
DESCRIPTION = ("Curated, audited, container-packaged MCP servers for authorized security work "
               "(reverse engineering, firmware and forensics, network recon, web, OSINT, secrets, "
               "password cracking), "
               "built by https://github.com/c0decave/axross-mcp-hub and pinned by digest.")
PENDING_NOTE = ("PENDING: these images have no published digest yet. axross refuses every entry "
                "without a digest; scripts/make_catalog.py fills them from the first CI run.")

# The same limits and patterns as axross core/mcp_catalog.py.
MAX_DESCRIPTION = 2000
MAX_SHORT = 200
MAX_ARGS = 32
MAX_ENV = 32
MAX_MOUNTS = 8
MAX_TAGS = 16
MAX_HOSTS = 16
NETWORKS = ("none", "allowlist", "full")
_SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,199}$")
_IMAGE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?"
                    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_TARGET = re.compile(r"^/(?:[A-Za-z0-9._-]+|\{name\})(?:/(?:[A-Za-z0-9._-]+|\{name\}))*$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}:[0-9]{1,5}$")

ENTRY_KEYS = ("id", "name", "title", "description", "category", "tags", "repository", "page",
              "license", "kind", "image", "tag", "digest", "args", "env", "mounts", "network",
              "hosts", "notes")
REQUIRED_KEYS = ("id", "name", "title", "description", "category", "repository", "license",
                 "kind", "image", "tag", "network")


class CatalogProblem(ValueError):
    """What is wrong, as text."""


def _text(entry: dict, key: str, limit: int, where: str, *, required: bool = False) -> None:
    value = entry.get(key)
    if value is None and not required:
        return
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise CatalogProblem(f"{where}: {key} must be a non-empty text of at most {limit} characters")
    if any(ord(c) < 32 and c not in "\n" for c in value):
        raise CatalogProblem(f"{where}: {key} contains control characters")


def _url(entry: dict, key: str, where: str) -> None:
    value = entry.get(key)
    if value is None:
        return
    parts = urlsplit(value) if isinstance(value, str) else None
    if not parts or parts.scheme not in ("http", "https") or not parts.hostname or len(value) > 500:
        raise CatalogProblem(f"{where}: {key} must be an http(s) URL")


def validate_entry(entry, *, where: str = "entry") -> None:
    """CatalogProblem unless *entry* is an entry axross accepts (digest optional)."""
    if not isinstance(entry, dict):
        raise CatalogProblem(f"{where}: not an object")
    unknown = sorted(set(entry) - set(ENTRY_KEYS))
    if unknown:
        raise CatalogProblem(f"{where}: unknown keys {', '.join(unknown)}")
    missing = [k for k in REQUIRED_KEYS if k not in entry]
    if missing:
        raise CatalogProblem(f"{where}: missing {', '.join(missing)}")
    if not isinstance(entry["name"], str) or not _SERVER_NAME.match(entry["name"]):
        raise CatalogProblem(f"{where}: name must be 1-32 letters, digits, '-' or '_'")
    if not isinstance(entry["id"], str) or not _ID.match(entry["id"]):
        raise CatalogProblem(f"{where}: id must be letters, digits and . _ / @ : + -")
    if entry["kind"] != "oci":
        raise CatalogProblem(f"{where}: kind must be oci (this hub publishes images)")
    image = entry["image"]
    if not isinstance(image, str) or not _IMAGE.match(image) or len(image) > 255:
        raise CatalogProblem(f"{where}: image must be registry/path without tag or digest")
    if image != IMAGE_PREFIX + entry["name"]:
        raise CatalogProblem(f"{where}: image must be {IMAGE_PREFIX}{entry['name']}")
    if not isinstance(entry["tag"], str) or not _TAG.match(entry["tag"]):
        raise CatalogProblem(f"{where}: tag must be letters, digits, . _ -")
    if "digest" in entry and (not isinstance(entry["digest"], str)
                              or not _DIGEST.match(entry["digest"])):
        raise CatalogProblem(f"{where}: digest must be sha256:<64 lower-case hex digits>")
    if entry["network"] not in NETWORKS:
        raise CatalogProblem(f"{where}: network must be one of {', '.join(NETWORKS)}")
    _text(entry, "title", MAX_SHORT, where, required=True)
    _text(entry, "description", MAX_DESCRIPTION, where, required=True)
    _text(entry, "category", 60, where, required=True)
    _text(entry, "license", MAX_SHORT, where, required=True)
    _text(entry, "notes", MAX_DESCRIPTION, where)
    _url(entry, "repository", where)
    _url(entry, "page", where)
    tags = entry.get("tags", [])
    if not isinstance(tags, list) or len(tags) > MAX_TAGS or not all(
            isinstance(t, str) and 0 < len(t) <= 40 for t in tags):
        raise CatalogProblem(f"{where}: tags must be at most {MAX_TAGS} texts of up to 40 characters")
    args = entry.get("args", [])
    if not isinstance(args, list) or len(args) > MAX_ARGS or not all(
            isinstance(a, str) and len(a) <= 1000 and not any(c in a for c in "\n\r\x00")
            for a in args):
        raise CatalogProblem(f"{where}: args must be at most {MAX_ARGS} single-line texts")
    env = entry.get("env", [])
    if not isinstance(env, list) or len(env) > MAX_ENV:
        raise CatalogProblem(f"{where}: env must be a list of at most {MAX_ENV} variables")
    for var in env:
        if not isinstance(var, dict) or not _ENV_NAME.match(str(var.get("name") or "")):
            raise CatalogProblem(f"{where}: an env variable needs a name of letters, digits and _")
    mounts = entry.get("mounts", [])
    if not isinstance(mounts, list) or len(mounts) > MAX_MOUNTS:
        raise CatalogProblem(f"{where}: mounts must be a list of at most {MAX_MOUNTS} folders")
    seen = set()
    for mount in mounts:
        target = mount.get("target") if isinstance(mount, dict) else None
        if (not isinstance(target, str) or len(target) > 200 or not _TARGET.match(target)
                or any(part in (".", "..") for part in target.split("/"))):
            raise CatalogProblem(f"{where}: mount target {target!r} is not an absolute path "
                                 "of letters, digits, . _ -")
        if target in seen:
            raise CatalogProblem(f"{where}: mount target {target} is there twice")
        seen.add(target)
    hosts = entry.get("hosts", [])
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS or not all(
            isinstance(h, str) and _HOST.match(h) for h in hosts):
        raise CatalogProblem(f"{where}: hosts must be at most {MAX_HOSTS} host:port entries")
    if entry["network"] == "allowlist" and not hosts:
        raise CatalogProblem(f"{where}: network allowlist needs hosts")


def load_servers(root: Path = ROOT) -> list[dict]:
    servers = []
    names = set()
    for path in sorted((root / "servers").glob("*/server.json")):
        where = str(path.relative_to(root))
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise CatalogProblem(f"{where}: not valid JSON ({exc})") from None
        if isinstance(entry, dict) and "digest" in entry:
            raise CatalogProblem(f"{where}: a digest belongs in digests.json, not in server.json")
        validate_entry(entry, where=where)
        if entry["name"] != path.parent.name:
            raise CatalogProblem(f"{where}: name {entry['name']!r} differs from its folder")
        if entry["name"] in names:
            raise CatalogProblem(f"{where}: name {entry['name']} is there twice")
        names.add(entry["name"])
        servers.append(entry)
    if not servers:
        raise CatalogProblem(f"no servers/*/server.json under {root}")
    return servers


def load_digests(path: Path) -> dict[str, str | None]:
    data = json.loads(path.read_text(encoding="utf-8"))
    images = data.get("images") if isinstance(data, dict) else None
    if not isinstance(images, dict):
        raise CatalogProblem(f"{path.name}: needs an object 'images' of name -> digest or null")
    for name, digest in images.items():
        if digest is not None and (not isinstance(digest, str) or not _DIGEST.match(digest)):
            raise CatalogProblem(f"{path.name}: {name}: {digest!r} is not sha256:<64 hex> or null")
    return dict(images)


def read_ci_digests(paths: list[Path]) -> dict[str, str]:
    """``digest-<name>.json`` files of the build workflow (``{"name", "image", "digest"}``),
    given as files or folders."""
    files: list[Path] = []
    for path in paths:
        files.extend(sorted(path.rglob("digest-*.json")) if path.is_dir() else [path])
    if not files:
        raise CatalogProblem("no digest-*.json files in " + ", ".join(map(str, paths)))
    out: dict[str, str] = {}
    for file in files:
        data = json.loads(file.read_text(encoding="utf-8"))
        name, image, digest = (data.get(k) if isinstance(data, dict) else None
                               for k in ("name", "image", "digest"))
        if not isinstance(name, str) or not _SERVER_NAME.match(name):
            raise CatalogProblem(f"{file.name}: no valid name")
        if image != IMAGE_PREFIX + name:
            raise CatalogProblem(f"{file.name}: image {image!r} is not {IMAGE_PREFIX}{name}")
        if not isinstance(digest, str) or not _DIGEST.match(digest):
            raise CatalogProblem(f"{file.name}: {digest!r} is not a sha256 digest")
        if name in out and out[name] != digest:
            raise CatalogProblem(f"{file.name}: two different digests for {name}")
        out[name] = digest
    return out


def build_catalog(servers: list[dict], digests: dict[str, str | None]) -> dict:
    unknown = sorted(set(digests) - {s["name"] for s in servers})
    if unknown:
        raise CatalogProblem(f"digests for servers that do not exist: {', '.join(unknown)}")
    entries, pending = [], []
    for server in servers:
        digest = digests.get(server["name"])
        source = {**server, "digest": digest} if digest else server
        entry = {k: source[k] for k in ENTRY_KEYS if k in source}  # axross's key order
        if not digest:
            pending.append(server["name"])
        validate_entry(entry, where=f"catalog entry {server['name']}")
        entries.append(entry)
    catalog = {
        "schema": SCHEMA,
        "version": VERSION,
        "title": TITLE,
        "description": DESCRIPTION if not pending else f"{DESCRIPTION} {PENDING_NOTE}",
        "state": "pending-digests" if pending else "pinned",
    }
    if pending:
        catalog["pending"] = pending
    catalog["entries"] = entries
    return catalog


def dump(catalog: dict) -> str:
    return json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"


def axross_check(catalog_path: Path, catalog: dict, axross_dir: Path) -> list[str]:
    """Problems found when axross's own validator reads *catalog_path*."""
    sys.path.insert(0, str(axross_dir))
    try:
        from core import mcp_catalog  # axross
    except ImportError as exc:
        return [f"cannot import axross's core.mcp_catalog from {axross_dir}: {exc}"]
    try:
        parsed, warnings = mcp_catalog.load_catalog_file(catalog_path, source="file:hub")
    except mcp_catalog.CatalogError as exc:
        return [f"axross refuses the whole catalog: {exc}"]
    problems = []
    by_id = {e.id: e for e in parsed}
    for entry in catalog["entries"]:
        got = by_id.get(entry["id"])
        if "digest" in entry:
            if got is None:
                problems.append(f"axross refused pinned entry {entry['name']}: "
                                + "; ".join(w for w in warnings if entry["name"] in w))
            elif (got.identifier, got.digest, got.network) != (
                    entry["image"], entry["digest"], entry["network"]):
                problems.append(f"axross read {entry['name']} differently: "
                                f"{got.identifier}@{got.digest} network {got.network}")
            elif [m.target for m in got.mounts] != [m["target"] for m in entry.get("mounts", [])]:
                problems.append(f"axross read the mounts of {entry['name']} differently")
        else:
            if got is not None:
                problems.append(f"axross accepted {entry['name']} although it has no digest")
            elif not any(entry["id"] in w and "digest" in w for w in warnings):
                problems.append(f"axross refused {entry['name']} for another reason: {warnings}")
    print(f"axross validator: {len(parsed)} entries accepted, {len(warnings)} refused")
    for warning in warnings:
        print(f"  refused: {warning}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="the hub repository")
    parser.add_argument("--digests", type=Path, help="default: ROOT/digests.json")
    parser.add_argument("--ci-digests", type=Path, nargs="+", default=[],
                        help="digest-<name>.json files (or folders) of a CI run")
    parser.add_argument("--write-digests", action="store_true",
                        help="store the --ci-digests in digests.json")
    parser.add_argument("--out", type=Path, help="default: ROOT/catalog.json")
    parser.add_argument("--check", action="store_true",
                        help="do not write; fail unless catalog.json is current (and pinned)")
    parser.add_argument("--allow-pending", action="store_true",
                        help="with --check: entries without digest are not a failure")
    parser.add_argument("--axross", type=Path, help="an axross checkout: also run its validator")
    opts = parser.parse_args(argv)
    root = opts.root.resolve()
    digests_path = opts.digests or root / "digests.json"
    out = opts.out or root / "catalog.json"
    try:
        servers = load_servers(root)
        digests = load_digests(digests_path)
        if opts.ci_digests:
            digests.update(read_ci_digests(opts.ci_digests))
            if opts.write_digests:
                data = json.loads(digests_path.read_text(encoding="utf-8"))
                data["images"] = {s["name"]: digests.get(s["name"]) for s in servers}
                digests_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        for server in servers:
            digests.setdefault(server["name"], None)
        catalog = build_catalog(servers, digests)
    except (CatalogProblem, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = dump(catalog)
    pending = catalog.get("pending", [])
    if not opts.check:
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out} - {len(catalog['entries'])} entries, "
              + (f"pending digests: {', '.join(pending)}" if pending else "all pinned"))
        return 0
    problems = []
    current = out.read_text(encoding="utf-8") if out.exists() else ""
    if current != text:
        problems.append(f"{out.name} is not what servers/*/server.json and "
                        f"{digests_path.name} give: run scripts/make_catalog.py")
    if pending and not opts.allow_pending:
        problems.append(f"digests pending for: {', '.join(pending)}")
    if opts.axross and out.exists():
        problems.extend(axross_check(out, json.loads(current or text), opts.axross.resolve()))
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print(f"OK: {out.name} is current - {len(catalog['entries'])} entries, "
              + (f"pending digests: {', '.join(pending)}" if pending else "all pinned"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
