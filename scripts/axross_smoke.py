#!/usr/bin/env python3
"""Check and run tests/axross-smoke.json - the smoke spec of every catalog entry.

tests/axross-smoke.json (schema ``axross-mcp-hub-smoke``, version 1) says, per catalog
entry, how to prove that the server works when axross starts it: which tools it must offer,
which files to put into which mounted folder, which network to grant, which local target to
start, one real call with a text its answer must contain, and one bad call that must be
refused with a text naming the problem. axross's own tests read the same file.

    scripts/axross_smoke.py --check                       # offline: spec vs catalog + tools
    scripts/axross_smoke.py --run yara capa --image yara=localhost/x:1 --image capa=...
    scripts/axross_smoke.py --run-all --from-catalog --target-host 10.88.0.1 --axross DIR

``--check`` validates the spec against catalog.json and servers/<name>/tools.json (exit 1
on any problem). ``--run`` / ``--run-all`` start each server with axross's run line
(``scripts/smoke_test.py``'s ``run_command``, which mirrors axross core/mcp_install.py):
the spec's files are written to a temporary folder per mount target, a target is started
in a disposable container when the spec names one, then initialize, tools/list (the
required tools, and exactly the tools of tools.json), the setup calls, the call and the
refused call. Images come from ``--image NAME=REF`` or, with ``--from-catalog``, from the
catalog's pinned ``image@digest``. An allowlist spec needs ``--axross DIR`` (axross's own
egress proxy); a target needs ``--target-host ADDR``: an address of this machine that the
server container reaches with the full network and that other machines cannot reach (a
host-only bridge address; with podman's pasta not 127.0.0.1). Standard library only.

Spec format, per server::

    {"name": "<catalog name>",
     "tools_required": ["<tool>", ...],
     "files": [{"target": "/work", "path": "<file name>", "base64": "...", "gzip": false}],
     "network": "none" | "full" | {"allowlist": ["host:port", ...]},
     "target": "<key of targets>",            # optional; args may use ${TARGET_HOST} ${TARGET_PORT}
     "live_needs_network": true,              # optional: the call reaches a public service
     "setup": [{"tool": "...", "args": {...}}],                     # optional, in order
     "call": {"tool": "...", "args": {...}, "expect_substring": "..."},
     "refused": {"tool": "...", "args": {...}, "expect_substring": "..."},
     "timeout_s": 300}

``${TARGET_HOST}`` and ``${TARGET_PORT}`` are replaced in args and expected texts. A call
passes when the answer has no JSON-RPC error, is not ``isError`` and its text
contains ``expect_substring``; a setup call when it has no JSON-RPC error and is not
``isError``; the refused call when its text contains ``expect_substring`` (the server's
own refusal message - proof that the bad value was refused, not run).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "tests" / "axross-smoke.json"
SCHEMA = "axross-mcp-hub-smoke"
VERSION = 1
MAX_TIMEOUT = 3600
SERVER_KEYS = {"name", "tools_required", "files", "network", "target", "live_needs_network",
               "setup", "call", "refused", "timeout_s", "notes"}
FILE_KEYS = {"target", "path", "base64", "gzip"}
TARGET_KEYS = {"image", "digest", "port", "command", "files", "serves", "source"}
_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}:[0-9]{1,5}$")
_TARGET_VARS = re.compile(r"\$\{TARGET_(?:HOST|PORT)\}")


def file_bytes(item: dict) -> bytes:
    """The content of a spec file entry (``base64``, gzip-compressed when ``gzip``)."""
    try:
        data = base64.b64decode(item["base64"], validate=True)
    except (binascii.Error, ValueError, TypeError, KeyError):
        raise ValueError("base64 is not valid base64") from None
    if item.get("gzip"):
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            raise ValueError("gzip is set but the data is not gzip") from None
    return data


def load_tools(root: Path = ROOT) -> dict[str, list[str]]:
    """servers/<name>/tools.json of every server that has one."""
    out = {}
    for path in sorted((root / "servers").glob("*/tools.json")):
        out[path.parent.name] = json.loads(path.read_text(encoding="utf-8"))["tools"]
    return out


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)


def _check_call(name: str, label: str, call, tools: list[str] | None, *, expect: bool,
                files: set[str], mounts: list[str], problems: list[str]) -> None:
    if not isinstance(call, dict) or not isinstance(call.get("tool"), str):
        problems.append(f"{name}: {label}: needs a tool")
        return
    if tools is not None and call["tool"] not in tools:
        problems.append(f"{name}: {label}: {call['tool']} is not a tool of the server")
    if not isinstance(call.get("args", {}), dict):
        problems.append(f"{name}: {label}: args must be an object")
    if expect and (not isinstance(call.get("expect_substring"), str)
                   or not call["expect_substring"]):
        problems.append(f"{name}: {label}: expect_substring must be a non-empty text")
    if label == "refused":
        return  # a refused call may name anything: that is its point
    for text in _strings(call.get("args", {})):
        for target in mounts:
            if text.startswith(target.rstrip("/") + "/") and text not in files:
                problems.append(f"{name}: {label}: {text} is not one of the spec's files")


def validate(spec: dict, catalog: dict, tools: dict[str, list[str]],
             root: Path = ROOT) -> list[str]:
    """Every problem of *spec* against *catalog* and the recorded *tools*, as texts."""
    problems: list[str] = []
    if spec.get("schema") != SCHEMA or spec.get("version") != VERSION:
        problems.append(f"schema/version must be {SCHEMA} {VERSION}")
    targets = spec.get("targets", {})
    for key, target in targets.items():
        where = f"target {key}"
        unknown = sorted(set(target) - TARGET_KEYS)
        if unknown:
            problems.append(f"{where}: unknown keys {', '.join(unknown)}")
        if not isinstance(target.get("image"), str) or "@" in target.get("image", "@"):
            problems.append(f"{where}: image must be a name without digest")
        if not isinstance(target.get("digest"), str) or not _DIGEST.match(target["digest"]):
            problems.append(f"{where}: digest must be sha256:<64 hex> (the image is pinned)")
        if not isinstance(target.get("port"), int) or not 1 <= target["port"] <= 65535:
            problems.append(f"{where}: port must be 1-65535")
        if not isinstance(target.get("command"), list) or not target["command"]:
            problems.append(f"{where}: command must be a non-empty list")
        if not isinstance(target.get("serves"), str) or not target["serves"]:
            problems.append(f"{where}: serves must say what the target serves")
        for item in target.get("files", []):
            try:
                file_bytes(item)
            except ValueError as exc:
                problems.append(f"{where}: file {item.get('path')}: {exc}")
    entries = {e["name"]: e for e in catalog.get("entries", [])}
    seen: dict[str, int] = {}
    for server in spec.get("servers", []):
        name = server.get("name", "?")
        seen[name] = seen.get(name, 0) + 1
        entry = entries.get(name)
        if entry is None:
            problems.append(f"{name}: no catalog entry of that name")
            continue
        unknown = sorted(set(server) - SERVER_KEYS)
        if unknown:
            problems.append(f"{name}: unknown keys {', '.join(unknown)}")
        known = tools.get(name)
        if known is None:
            problems.append(f"{name}: no servers/{name}/tools.json (the recorded tool list)")
        required = server.get("tools_required")
        if not isinstance(required, list) or not required:
            problems.append(f"{name}: tools_required must list a few tools")
            required = []
        for tool in required:
            if known is not None and tool not in known:
                problems.append(f"{name}: tools_required: {tool} is not a tool of the server")
        mounts = [m["target"] for m in entry.get("mounts", [])]
        files: set[str] = set()
        covered: set[str] = set()
        for item in server.get("files", []):
            path = item.get("path", "?")
            unknown = sorted(set(item) - FILE_KEYS)
            if unknown:
                problems.append(f"{name}: file {path}: unknown keys {', '.join(unknown)}")
            if not isinstance(path, str) or not _FILE_NAME.match(path):
                problems.append(f"{name}: file {path}: path must be a plain file name")
            if item.get("target") not in mounts:
                problems.append(f"{name}: file {path}: {item.get('target')} is not a mount "
                                "target of the catalog entry")
            else:
                covered.add(item["target"])
                files.add(f"{item['target'].rstrip('/')}/{path}")
            try:
                file_bytes(item)
            except ValueError as exc:
                problems.append(f"{name}: file {path}: {exc}")
        for mount in entry.get("mounts", []):
            if mount.get("required") and mount["target"] not in covered:
                problems.append(f"{name}: required mount {mount['target']} gets no files")
        network = server.get("network")
        if network == "full":
            if entry["network"] != "full":
                problems.append(f"{name}: network full but the catalog entry has network "
                                f"{entry['network']}")
        elif isinstance(network, dict) and set(network) == {"allowlist"}:
            hosts = network["allowlist"]
            if entry["network"] != "allowlist":
                problems.append(f"{name}: network allowlist but the catalog entry has network "
                                f"{entry['network']}")
            if not isinstance(hosts, list) or not hosts:
                problems.append(f"{name}: allowlist needs host:port entries")
                hosts = []
            for host in hosts:
                if not isinstance(host, str) or not _HOST.match(host):
                    problems.append(f"{name}: allowlist host {host!r} is not host:port")
                elif host not in entry.get("hosts", []):
                    problems.append(f"{name}: allowlist host {host} is not in the catalog entry")
        elif network != "none":
            problems.append(f"{name}: network must be none, full or {{\"allowlist\": [...]}}")
        if server.get("live_needs_network") and not isinstance(network, dict):
            problems.append(f"{name}: live_needs_network is only for allowlisted public "
                            "services (a scanner gets a local target instead)")
        calls = [("call", server.get("call"), True), ("refused", server.get("refused"), True)]
        calls += [(f"setup {i}", c, False) for i, c in enumerate(server.get("setup", []), 1)]
        for label, call, expect in calls:
            _check_call(name, label, call, known, expect=expect, files=files, mounts=mounts,
                        problems=problems)
        uses_target = any(_TARGET_VARS.search(t) for _, c, _ in calls for t in _strings(c))
        if "target" in server:
            if server["target"] not in targets:
                problems.append(f"{name}: target {server['target']} does not exist")
        elif uses_target:
            problems.append(f"{name}: uses ${{TARGET_HOST}}/${{TARGET_PORT}} but names no target")
        timeout = server.get("timeout_s")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT:
            problems.append(f"{name}: timeout_s must be 1-{MAX_TIMEOUT}")
    for name in entries:
        if name not in seen:
            problems.append(f"{name}: catalog entry has no smoke spec")
    for name, count in seen.items():
        if count > 1:
            problems.append(f"{name}: more than one smoke spec")
    return problems


# --- running --------------------------------------------------------------------------

def _smoke_test_module():
    spec = importlib.util.spec_from_file_location("smoke_test", ROOT / "scripts" / "smoke_test.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_files(items: list[dict], base: Path) -> dict[str, Path]:
    """The spec's files under *base*, one folder per mount target."""
    folders: dict[str, Path] = {}
    for item in items:
        folder = folders.get(item["target"])
        if folder is None:
            folder = base / f"m{len(folders)}"
            folder.mkdir(mode=0o755)
            folders[item["target"]] = folder
        path = folder / item["path"]
        path.write_bytes(file_bytes(item))
        path.chmod(0o644)
    return folders


class Target:
    """A disposable container serving a spec target on HOST:<free port>."""

    def __init__(self, engine: str, key: str, target: dict, host: str, base: Path) -> None:
        self.engine = engine
        self.name = f"axross-hub-smoke-target-{key}-{secrets.token_hex(4)}"
        folder = base / f"target-{key}"
        folder.mkdir(mode=0o755)
        for item in target["files"]:
            path = folder / item["path"]
            path.write_bytes(file_bytes(item))
            path.chmod(0o644)
        mount = target["files"][0]["target"]
        image = f"{target['image']}@{target['digest']}"
        argv = [engine, "run", "-d", "--rm", f"--name={self.name}", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--read-only", "--memory=256m",
                f"--publish={host}::{target['port']}", f"--volume={folder}:{mount}:ro",
                image, *target["command"]]
        subprocess.run(argv, check=True, capture_output=True, timeout=300)
        port = subprocess.run([engine, "port", self.name, f"{target['port']}/tcp"],
                              check=True, capture_output=True, text=True, timeout=60).stdout
        self.host = host
        self.port = int(port.strip().splitlines()[0].rsplit(":", 1)[1])
        deadline = time.monotonic() + 60
        while True:
            try:
                socket.create_connection((host, self.port), timeout=2).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError(f"target {key} does not answer on {host}:{self.port}")
                time.sleep(0.5)

    def stop(self) -> None:
        subprocess.run([self.engine, "rm", "-f", self.name], capture_output=True, timeout=120)


def _is_error(message: dict) -> bool:
    return "error" in message or bool(message.get("result", {}).get("isError"))


def run_one(server: dict, spec: dict, image: str, opts, st) -> dict:
    """Run one server's smoke spec; a report with ``ok``."""
    name = server["name"]
    report = {"name": name, "image": image, "checks": []}
    base = Path(tempfile.mkdtemp(prefix=f"axross-hub-smoke-{name}-"))
    os.chmod(base, 0o755)
    target = proxy = session = None
    ok = True
    try:
        folders = _write_files(server.get("files", []), base)
        variables = {}
        if "target" in server:
            if not opts.target_host:
                raise RuntimeError("this spec starts a target: pass --target-host ADDR")
            target = Target(opts.engine, server["target"], spec["targets"][server["target"]],
                            opts.target_host, base)
            variables = {"TARGET_HOST": target.host, "TARGET_PORT": str(target.port)}
        network = server["network"]
        hosts = []
        if isinstance(network, dict):
            hosts, network = network["allowlist"], "allowlist"
            if not opts.axross:
                raise RuntimeError("an allowlist spec needs --axross DIR (axross's egress proxy)")
            proxy = st.start_proxy(hosts, opts.axross)
        read_fd, write_fd = os.pipe()
        os.write(write_fd, st.env_file({}, proxy.port if proxy else None))
        os.close(write_fd)
        mounts = [(str(folder), mount, False) for mount, folder in folders.items()]
        argv = st.run_command(f"hubsmoke-{name}", image, network=network, mounts=mounts,
                              program=opts.engine, env_fd=read_fd, run_id=secrets.token_hex(4),
                              egress_port=proxy.port if proxy else "")
        report["argv"] = argv
        session = st.Session(argv, read_fd)
        os.close(read_fd)
        timeout = server["timeout_s"]
        init = session.request("initialize", {
            "protocolVersion": st.PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "axross-mcp-hub-axross-smoke", "version": "1"}}, 120)
        report["server"] = init.get("result", {}).get("serverInfo", {})
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        names = [t.get("name") for t in
                 session.request("tools/list", {}, 60).get("result", {}).get("tools", [])]
        missing = [t for t in server["tools_required"] if t not in names]
        report["checks"].append({"check": "tools_required", "ok": not missing, "missing": missing})
        ok &= not missing
        tools_file = ROOT / "servers" / name / "tools.json"
        ok &= st.check_tools_file(report, names, str(tools_file))
        steps = [("setup", c) for c in server.get("setup", [])]
        steps += [("call", server["call"]), ("refused", server["refused"])]
        for kind, call in steps:
            args = st.substitute(call.get("args", {}), variables)
            started = time.monotonic()
            answer = session.request("tools/call", {"name": call["tool"], "arguments": args},
                                     timeout)
            text = st.result_text(answer)
            expect = st.substitute(call.get("expect_substring", ""), variables)
            if kind == "setup":
                passed = not _is_error(answer)
            elif kind == "call":
                passed = not _is_error(answer) and expect in text
            else:
                passed = expect in text
            report["checks"].append({"check": f"{kind} {call['tool']}", "ok": passed,
                                     "expect": expect, "seconds": round(time.monotonic() - started, 2),
                                     "text": text[:1200]})
            ok &= passed
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        ok = False
        report["exception"] = f"{type(exc).__name__}: {exc}"
    finally:
        if session is not None:
            report["stderr_tail"] = session.close()[-2000:]
        if proxy is not None:
            proxy.close()
        if target is not None:
            target.stop()
        shutil.rmtree(base, ignore_errors=True)
    report["ok"] = bool(ok)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--spec", type=Path, default=SPEC)
    parser.add_argument("--check", action="store_true", help="validate the spec offline")
    parser.add_argument("--run", nargs="+", default=[], metavar="NAME", help="run these specs")
    parser.add_argument("--run-all", action="store_true", help="run every spec")
    parser.add_argument("--image", action="append", default=[], metavar="NAME=REF")
    parser.add_argument("--from-catalog", action="store_true",
                        help="images not given by --image: the catalog's image@digest")
    parser.add_argument("--engine", default="podman")
    parser.add_argument("--axross", help="an axross checkout (its egress proxy, for allowlists)")
    parser.add_argument("--target-host", help="host address targets are published on")
    parser.add_argument("--skip-live-network", action="store_true",
                        help="skip specs whose call reaches a public service")
    opts = parser.parse_args(argv)
    spec = json.loads(opts.spec.read_text(encoding="utf-8"))
    catalog = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
    problems = validate(spec, catalog, load_tools(ROOT), ROOT)
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if opts.check or problems:
        if not problems:
            print(f"OK: {opts.spec.name} covers all {len(catalog['entries'])} catalog entries")
        return 1 if problems else 0
    images = dict(i.split("=", 1) for i in opts.image)
    entries = {e["name"]: e for e in catalog["entries"]}
    chosen = [s for s in spec["servers"] if opts.run_all or s["name"] in opts.run]
    unknown = sorted(set(opts.run) - {s["name"] for s in spec["servers"]})
    if unknown or not chosen:
        parser.error(f"no such spec: {', '.join(unknown) or '(none chosen)'}")
    st = _smoke_test_module()
    reports, ok = [], True
    for server in chosen:
        if opts.skip_live_network and server.get("live_needs_network"):
            reports.append({"name": server["name"], "skipped": "live_needs_network"})
            continue
        image = images.get(server["name"])
        if image is None and opts.from_catalog:
            entry = entries[server["name"]]
            if "digest" not in entry:
                reports.append({"name": server["name"], "ok": False,
                                "exception": "no digest in catalog.json: pass --image"})
                ok = False
                continue
            image = f"{entry['image']}@{entry['digest']}"
        if image is None:
            parser.error(f"{server['name']}: pass --image {server['name']}=REF or --from-catalog")
        report = run_one(server, spec, image, opts, st)
        ok &= report["ok"]
        reports.append(report)
        print(f"{server['name']}: {'ok' if report['ok'] else 'FAIL'} "
              + " ".join(f"{c['check']}:{'ok' if c['ok'] else 'FAIL'}" for c in report["checks"])
              + (f" ({report['exception']})" if "exception" in report else ""), file=sys.stderr)
    print(json.dumps(reports, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
