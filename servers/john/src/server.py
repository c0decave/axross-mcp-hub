#!/usr/bin/env python3
"""John the Ripper MCP server (axross-mcp-hub): password hash cracking with John the
Ripper (jumbo), CPU only.

Tools:
    - crack: crack hashes with a wordlist (+ rules), single crack or incremental mode,
      for a bounded time
    - extract_hash: turn a protected file under /work (zip, rar, PDF, Office, SSH key,
      KeePass) into a hash line for crack (the *2john helpers)
    - list_formats: the hash formats this build knows

Hashes go to a private temporary file, never onto a command line; wordlists and files
come only from /work (the folder axross mounts) or the bundled password.lst. Every argument
is validated, nothing runs through a shell, and every run has a time limit. Crack only
hashes you are authorized to crack.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
import tempfile

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("john-mcp")

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

RUN = "/opt/john/run"
JOHN = f"{RUN}/john"
BUILTIN_WORDLIST = f"{RUN}/password.lst"
MODES = ("wordlist", "single", "incremental")
_FORMAT = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
#: extract_hash: the helper and the interpreter it needs
HELPERS = {
    "zip": [f"{RUN}/zip2john"],
    "rar": [f"{RUN}/rar2john"],
    "pdf": ["/opt/venv/bin/python", f"{RUN}/pdf2john.py"],
    "office": ["/opt/venv/bin/python", f"{RUN}/office2john.py"],
    "ssh": ["/opt/venv/bin/python", f"{RUN}/ssh2john.py"],
    "keepass": [f"{RUN}/keepass2john"],
}
MAX_HASHES = 10000
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

mcp = FastMCP("john-mcp")


def _hashes(value) -> str:
    if not isinstance(value, list) or not value or len(value) > MAX_HASHES:
        raise ArgumentError(f"hashes: a list of 1-{MAX_HASHES} hash lines")
    lines = [_line(h, "hashes", 16384, empty=False) for h in value]
    return "\n".join(lines) + "\n"


def _format(value) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, str) or not _FORMAT.match(value):
        raise ArgumentError("format: a john format name such as raw-md5, nt, sha512crypt")
    return [f"--format={value}"]


def _env() -> dict:
    return {"PATH": "/usr/bin:/bin", "HOME": "/tmp"}


def _crack(hashes: str, fmt: list[str], mode: list[str], seconds: int) -> dict:
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        hashfile = os.path.join(tmp, "hashes.txt")
        with open(hashfile, "w", encoding="utf-8") as handle:
            handle.write(hashes)
        common = [f"--pot={tmp}/john.pot", *fmt]
        code, out, err = _run([JOHN, f"--session={tmp}/session", f"--max-run-time={seconds}",
                               "--no-log", *common, *mode, hashfile], seconds + 60, env=_env())
        status = (out + err).strip()
        code2, shown, err2 = _run([JOHN, "--show", *common, hashfile], 120, env=_env())
    status, shown = _ANSI.sub("", status), _ANSI.sub("", shown)
    cracked, summary = [], ""
    for line in shown.splitlines():
        if re.match(r"^\d+ password hash(es)? cracked", line):
            summary = line
        elif ":" in line:
            cracked.append(line)
    if code != 0 and not cracked:
        raise ArgumentError(f"john failed (exit {code}): {_clip(status, 3000)}")
    return {"cracked": cracked, "summary": summary or _clip(err2.strip(), 500),
            "log": _clip(status, 4000)}


@mcp.tool()
async def crack(hashes: list[str], mode: str = "wordlist", format: str = "",
                wordlist: str = "", rules: bool = True, max_seconds: int = 120) -> dict:
    """Crack *hashes* (one hash or user:hash per entry). mode: wordlist (with *wordlist*, a
    file under /work, default the bundled password.lst, and word mangling *rules*), single
    (variations of user names) or incremental (brute force); format: a john format name
    (see list_formats; default: autodetect); max_seconds 1-1800."""
    try:
        text = _hashes(hashes)
        fmt = _format(format)
        if mode not in MODES:
            raise ArgumentError(f"mode: one of {', '.join(MODES)}")
        if mode == "wordlist":
            words = _input_path(wordlist, "wordlist") if wordlist else BUILTIN_WORDLIST
            mode_args = [f"--wordlist={words}"] + (["--rules"] if rules is not False else [])
        elif mode == "single":
            mode_args = ["--single"]
        else:
            mode_args = ["--incremental"]
        seconds = _int(max_seconds, "max_seconds", 1, 1800, 120)
        result = await asyncio.to_thread(_crack, text, fmt, mode_args, seconds)
        return {"mode": mode, "hashes": len(hashes), **result}
    except ArgumentError as exc:
        return {"error": str(exc)}


@mcp.tool()
async def extract_hash(kind: str, filepath: str, timeout: int = 120) -> dict:
    """The crackable hash of a protected file under /work. kind: zip, rar, pdf, office,
    ssh (private key) or keepass. Feed the result to crack."""
    try:
        if kind not in HELPERS:
            raise ArgumentError(f"kind: one of {', '.join(HELPERS)}")
        path = _input_path(filepath, "filepath")
        code, out, err = await asyncio.to_thread(
            _run, [*HELPERS[kind], path], _int(timeout, "timeout", 1, 600, 120), env=_env())
        lines = [l for l in out.splitlines() if ":" in l]
        if not lines:
            raise ArgumentError(f"{kind}2john found no hash (exit {code}): {_clip(err.strip(), 2000)}")
        return {"filepath": path, "kind": kind, "hashes": lines[:100]}
    except ArgumentError as exc:
        return {"error": str(exc)}


@mcp.tool()
async def list_formats(contains: str = "") -> dict:
    """The hash formats of this John the Ripper build, optionally only those whose name
    contains *contains* (case-insensitive)."""
    try:
        needle = _line(contains, "contains", 40).lower()
        code, out, err = await asyncio.to_thread(_run, [JOHN, "--list=formats"], 60, env=_env())
        names = [n.strip() for n in out.replace("\n", ",").split(",") if n.strip()]
        names = [n for n in names if needle in n.lower()]
        return {"formats": len(names), "names": names}
    except ArgumentError as exc:
        return {"error": str(exc)}


if __name__ == "__main__":
    mcp.run("stdio")
