#!/usr/bin/env python3
"""FLOSS MCP server (axross-mcp-hub): obfuscated strings in malware with Mandiant FLOSS.

Tools:
    - floss_strings: static, stack, tight and decoded strings of a PE file or shellcode
      (static strings only for other formats), as JSON
    - floss_languages: which string types FLOSS can extract (the --only values)

Samples are read only from /work (the folder axross mounts) and passed as absolute paths;
every argument is validated, nothing runs through a shell. FLOSS emulates code to decode
strings in-process (vivisect); it never executes the sample.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("floss-mcp")

# --- axross-mcp-hub: argument checks and process runner -------------------------------
#: Input files are read only from these folders (axross mounts the user's folder at /work).
INPUT_ROOTS = tuple(p for p in os.environ.get("MCP_INPUT_ROOTS", "/work").split(":") if p)
#: Characters of tool output returned at most (the rest is cut, and the answer says so).
MAX_OUTPUT = 200_000
MAX_TIMEOUT = 3600


class ArgumentError(ValueError):
    """A tool argument that is not accepted; the text says why."""


def _input_path(value, what: str = "path", *, kind: str = "file") -> str:
    """*value* as an absolute, symlink-free path under INPUT_ROOTS (relative paths are
    taken from the first root). It starts with "/", so it can never become an option.
    *kind*: file, dir or any."""
    roots = [os.path.realpath(r) for r in INPUT_ROOTS]
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 4096:
        raise ArgumentError(f"{what}: a path under {', '.join(INPUT_ROOTS)}")
    path = os.path.realpath(value if os.path.isabs(value) else os.path.join(roots[0], value))
    if not any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots):
        raise ArgumentError(f"{what}: only paths under {', '.join(INPUT_ROOTS)} are read "
                            "(mount the folder there)")
    if kind == "file" and not os.path.isfile(path):
        raise ArgumentError(f"{what}: {value} is not a file")
    if kind == "dir" and not os.path.isdir(path):
        raise ArgumentError(f"{what}: {value} is not a folder")
    if kind == "any" and not os.path.exists(path):
        raise ArgumentError(f"{what}: {value} not found")
    return path


def _int(value, name: str, low: int, high: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ArgumentError(f"{name}: an integer from {low} to {high}")
    return value


def _line(value, name: str, limit: int = 1000, *, empty: bool = True) -> str:
    """One line of text: no NUL, CR or LF, at most *limit* characters."""
    if value is None and empty:
        return ""
    if not isinstance(value, str) or len(value) > limit or any(c in value for c in "\x00\r\n"):
        raise ArgumentError(f"{name}: one line of at most {limit} characters")
    if not value and not empty:
        raise ArgumentError(f"{name}: may not be empty")
    return value


def _clip(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... cut: {len(text) - limit} more characters]"


def _run(argv: list[str], timeout: int, *, env: dict | None = None,
         stdin: bytes | None = None) -> tuple[int, str, str]:
    """Run *argv* (a list - never a shell) with a deadline; (exit code, stdout, stderr)."""
    feed = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, cwd="/tmp", env=env,
                              **feed)
    except subprocess.TimeoutExpired:
        raise ArgumentError(f"{os.path.basename(argv[0])} did not finish within {timeout} s "
                            "(raise timeout)") from None
    return (done.returncode, done.stdout.decode("utf-8", "replace"),
            done.stderr.decode("utf-8", "replace"))
# --------------------------------------------------------------------------------------

FLOSS = "floss"
DEFAULT_TIMEOUT = 600
TYPES = ("static", "stack", "tight", "decoded")
FORMATS = ("auto", "pe", "sc32", "sc64")

mcp = FastMCP("floss-mcp")


def _strings(block, limit: int) -> tuple[int, list]:
    items = block if isinstance(block, list) else []
    out = []
    for item in items[:limit]:
        if isinstance(item, dict):
            row = {"string": item.get("string")}
            for key in ("offset", "encoding", "function", "decoding_routine",
                        "address", "address_type", "program_counter"):
                if item.get(key) not in (None, ""):
                    row[key] = item[key]
            out.append(row)
    return len(items), out


@mcp.tool()
async def floss_strings(filepath: str, only: list[str] | None = None, min_length: int = 4,
                        file_format: str = "auto", max_strings: int = 2000,
                        timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Extract strings with FLOSS. only: some of static, stack, tight, decoded (default
    all); min_length 3-64; file_format: auto, pe, sc32 or sc64 (shellcode); max_strings per
    type 1-50000. Decoding needs a PE file or shellcode; other formats get static strings."""
    try:
        path = _input_path(filepath, "filepath")
        kinds = only or list(TYPES)
        if not isinstance(kinds, list) or not kinds or not all(k in TYPES for k in kinds):
            raise ArgumentError(f"only: a list of {', '.join(TYPES)}")
        if file_format not in FORMATS:
            raise ArgumentError(f"file_format: one of {', '.join(FORMATS)}")
        argv = [FLOSS, "-j", "--disable-progress", "-n",
                str(_int(min_length, "min_length", 3, 64, 4)), "--format", file_format,
                "--only", *dict.fromkeys(kinds), "--", path]
        limit = _int(max_strings, "max_strings", 1, 50000, 2000)
        code, out, err = await asyncio.to_thread(
            _run, argv, _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        try:
            data = json.loads(out)
        except ValueError:
            raise ArgumentError(f"floss failed (exit {code}): {_clip(err.strip(), 3000)}") from None
        strings = data.get("strings") or {}
        answer = {"filepath": path, "meta": {k: v for k, v in (data.get("metadata") or {}).items()
                                             if k in ("file_path", "imagebase", "min_length",
                                                      "runtime", "language", "language_version")}}
        for kind, key in (("static", "static_strings"), ("stack", "stack_strings"),
                          ("tight", "tight_strings"), ("decoded", "decoded_strings")):
            if key in strings:
                total, rows = _strings(strings[key], limit)
                answer[kind] = {"count": total, "returned": len(rows), "strings": rows}
        if code != 0:
            answer["warning"] = _clip(err.strip(), 2000)
        return answer
    except ArgumentError as exc:
        return {"error": str(exc)}


@mcp.tool()
async def floss_languages() -> dict:
    """The string types FLOSS extracts and what they mean."""
    return {"types": {
        "static": "strings stored in the file (like strings(1)), also UTF-16LE",
        "stack": "strings built on the stack at run time (emulated)",
        "tight": "stack strings decoded in place in tight loops (emulated)",
        "decoded": "strings decoded by routines FLOSS identifies and emulates",
    }, "formats": list(FORMATS), "notes": "Go and Rust binaries get language-aware static strings."}


if __name__ == "__main__":
    mcp.run("stdio")
