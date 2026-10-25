#!/usr/bin/env python3
"""Start a hub image exactly the way axross starts a catalog server and talk MCP to it.

The container gets axross's run line (core/mcp_install.py, ``RUN_FLAGS`` and
``run_command``): ``--rm -i --init --pull=never --log-driver=none --cap-drop=ALL
--security-opt=no-new-privileges --read-only --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m
--pids-limit=128 --memory=512m``, the environment through a pipe (``--env-file=/dev/fd/N``),
``--network=none`` unless the spec asks for the full network, and folders as
``--volume=HOST:TARGET:ro|rw`` with ``--user=0:0``.

Then: ``initialize``, ``notifications/initialized``, ``tools/list`` and every call of
the spec (``servers/<name>/smoke.json``), each checked for an expected text.

    scripts/smoke_test.py --image IMAGE --spec servers/yara/smoke.json --var FIXTURES=/abs/dir

``${NAME}`` in the spec is replaced by ``--var NAME=VALUE``. Exit status 0 when every
check passed. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import selectors
import subprocess
import sys
import time

#: Mirrors axross core/mcp_install.py RUN_FLAGS (checked against it when axross is at hand).
RUN_FLAGS = (
    "--rm", "-i", "--init", "--pull=never", "--log-driver=none",
    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
    "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m", "--pids-limit=128", "--memory=512m",
)
PROTOCOL_VERSION = "2025-06-18"


def run_command(name: str, image: str, *, network: str = "none", mounts=(), args=(),
                program: str = "podman", env_fd: int | str = "AXROSS_ENV_FD",
                run_id: str = "AXROSS_RUN_ID") -> list[str]:
    """The ``podman run`` line axross builds for a container server."""
    argv = [program, "run", *RUN_FLAGS, f"--name=axross-mcp-{name}-{run_id}",
            f"--label=io.axross.mcp={name}", f"--env-file=/dev/fd/{env_fd}"]
    if network == "none":
        argv.append("--network=none")
    elif network != "full":
        raise ValueError("network: none or full (the allowlist needs axross's egress proxy)")
    if mounts:
        argv.append("--user=0:0")
        for host, target, writable in mounts:
            argv.append(f"--volume={host}:{target}:{'rw' if writable else 'ro'}")
    return [*argv, image, *args]


def substitute(value, variables: dict[str, str]):
    if isinstance(value, str):
        def one(match):
            key = match.group(1)
            if key not in variables:
                raise KeyError(f"the spec uses ${{{key}}}: pass --var {key}=VALUE")
            return variables[key]
        return re.sub(r"\$\{([A-Z0-9_]+)\}", one, value)
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    return value


class Session:
    def __init__(self, argv: list[str], env_fd: int) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, pass_fds=(env_fd,))
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.proc.stdout, selectors.EVENT_READ)
        self.buf = b""
        self.next_id = 1

    def send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message).encode() + b"\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict, timeout: float) -> dict:
        ident = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    raise RuntimeError(f"not JSON-RPC on stdout: {line[:200]!r}") from None
                if message.get("id") == ident and ("result" in message or "error" in message):
                    return message
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"{method}: no answer within {timeout:g} s")
            if not self.sel.select(left):
                continue
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError(f"{method}: the server closed stdout (exit {self.proc.poll()})")
            self.buf += chunk

    def close(self) -> str:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        return self.proc.stderr.read().decode("utf-8", "replace")


def result_text(message: dict) -> str:
    if "error" in message:
        return "JSON-RPC error: " + json.dumps(message["error"])
    content = message.get("result", {}).get("content") or []
    return "\n".join(c.get("text", "") for c in content if isinstance(c, dict))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", required=True, help="image reference or ID")
    parser.add_argument("--spec", required=True, help="servers/<name>/smoke.json")
    parser.add_argument("--var", action="append", default=[], help="NAME=VALUE for ${NAME}")
    parser.add_argument("--engine", default="podman", help="podman (default) or docker")
    parser.add_argument("--list-only", action="store_true",
                        help="initialize and tools/list only (no calls, no folders)")
    parser.add_argument("--print-argv", action="store_true")
    parser.add_argument("--max-text", type=int, default=1500, help="result text shown per call")
    opts = parser.parse_args(argv)

    variables = dict(v.split("=", 1) for v in opts.var)
    with open(opts.spec, encoding="utf-8") as handle:
        spec = json.load(handle)
    name = spec["name"]
    network = spec.get("network", "none")
    mounts = [] if opts.list_only else [
        (substitute(m["host"], variables), m["target"], bool(m.get("writable")))
        for m in spec.get("mounts", [])
    ]
    read_fd, write_fd = os.pipe()
    os.close(write_fd)  # axross writes the chosen environment here; the spec sets none
    argv = run_command(f"smoke-{name}", opts.image, network=network, mounts=mounts,
                       args=spec.get("args", []), program=opts.engine, env_fd=read_fd,
                       run_id=secrets.token_hex(4))
    if opts.print_argv:
        print("argv:", json.dumps(argv))
    session = Session(argv, read_fd)
    os.close(read_fd)
    report = {"name": name, "image": opts.image, "network": network, "checks": []}
    ok = True
    try:
        init = session.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "axross-mcp-hub-smoke", "version": "1"}},
            spec.get("start_timeout", 60))
        info = init.get("result", {}).get("serverInfo", {})
        report["server"] = info
        report["protocolVersion"] = init.get("result", {}).get("protocolVersion")
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = session.request("tools/list", {}, 60).get("result", {}).get("tools", [])
        names = [t.get("name") for t in tools]
        report["tools"] = names
        missing = [t for t in spec.get("expect_tools", []) if t not in names]
        report["checks"].append({"check": "tools/list", "ok": not missing, "missing": missing})
        ok &= not missing
        for call in [] if opts.list_only else spec.get("calls", []):
            arguments = substitute(call.get("arguments", {}), variables)
            started = time.monotonic()
            answer = session.request("tools/call", {"name": call["tool"], "arguments": arguments},
                                     call.get("timeout", 120))
            text = result_text(answer)
            expect = substitute(call.get("expect", ""), variables)
            passed = expect in text and "error" not in answer
            if call.get("expect_error"):
                passed = expect in text
            report["checks"].append({
                "check": f"tools/call {call['tool']}", "arguments": arguments, "ok": passed,
                "expect": expect, "seconds": round(time.monotonic() - started, 2),
                "text": text[: opts.max_text]})
            ok &= passed
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        ok = False
        report["exception"] = f"{type(exc).__name__}: {exc}"
    finally:
        report["stderr_tail"] = session.close()[-3000:]
    report["ok"] = bool(ok)
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
