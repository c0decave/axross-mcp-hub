#!/usr/bin/env python3
"""The Sleuth Kit MCP server (axross-mcp-hub): disk image forensics.

Tools:
    - partitions: the partition table of an image (mmls)
    - filesystem_info: the file system at an offset (fsstat)
    - list_files: files and directories, deleted ones too (fls)
    - file_metadata: the metadata of one inode / MFT entry (istat)
    - read_file: the content of one file, as text or hex, bounded (icat)
    - extract_file: write one file's content to /out (icat; needs a writable /out)
    - timeline: a MAC timeline of the file system (fls -m | mactime)

Images (raw/dd, split raw, E01 when libewf supports it) are read only from /work, the
folder axross mounts. Every argument is validated and the image path is absolute, so no
value can become an option; nothing runs through a shell and nothing writes to the image.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
import threading

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("sleuthkit-mcp")

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

DEFAULT_TIMEOUT = 300
#: An inode or NTFS MFT address: 12 or 12-128-1
_INODE = re.compile(r"^[0-9]{1,20}(?:-[0-9]{1,10}-[0-9]{1,10})?$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_READ = 1 << 20

mcp = FastMCP("sleuthkit-mcp")


def _offset(value) -> list[str]:
    """-o SECTORS for a file system inside a partitioned image (0 = none)."""
    sectors = _int(value, "offset", 0, 1 << 40, 0)
    return ["-o", str(sectors)] if sectors else []


def _inode(value) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        value = str(value)
    if not isinstance(value, str) or not _INODE.match(value):
        raise ArgumentError("inode: a number such as 12, or an NTFS address such as 64-128-1")
    return value


async def _tool(argv: list[str], timeout) -> str:
    code, out, err = await asyncio.to_thread(
        _run, argv, _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
    if code != 0:
        raise ArgumentError(f"{argv[0]} failed (exit {code}): {_clip(err.strip() or out.strip(), 2000)}")
    return out


def _error(exc: Exception) -> dict:
    return {"error": str(exc)}


@mcp.tool()
async def partitions(image: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The partition table (DOS, GPT, BSD, Mac, Sun) of a disk image: start sectors for
    the offset argument of the other tools (mmls)."""
    try:
        path = _input_path(image, "image")
        return {"image": path, "partitions": _clip(await _tool(["mmls", "-B", path], timeout))}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def filesystem_info(image: str, offset: int = 0, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The file system at *offset* sectors (0 for an image of a single file system):
    type, label, sizes, layout (fsstat)."""
    try:
        path = _input_path(image, "image")
        out = await _tool(["fsstat", *_offset(offset), path], timeout)
        return {"image": path, "filesystem": _clip(out)}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def list_files(image: str, offset: int = 0, directory_inode: str | None = None,
                     recursive: bool = False, deleted_only: bool = False,
                     timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Files and directories of the file system, with inode addresses; deleted entries
    are marked with *. directory_inode: list that directory (default: the root);
    recursive: the whole tree; deleted_only: only deleted entries (fls)."""
    try:
        path = _input_path(image, "image")
        argv = ["fls", "-p", *_offset(offset)]
        if recursive is True:
            argv.append("-r")
        if deleted_only is True:
            argv.append("-d")
        argv.append(path)
        if directory_inode is not None:
            argv.append(_inode(directory_inode))
        out = await _tool(argv, timeout)
        return {"image": path, "entries": len(out.splitlines()), "files": _clip(out)}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def file_metadata(image: str, inode: str, offset: int = 0,
                        timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The metadata of one inode / MFT entry: times, size, owner, data runs (istat)."""
    try:
        path = _input_path(image, "image")
        out = await _tool(["istat", *_offset(offset), path, _inode(inode)], timeout)
        return {"image": path, "metadata": _clip(out)}
    except ArgumentError as exc:
        return _error(exc)


def _icat(path: str, inode: str, offset, limit: int, timeout: int) -> tuple[bytes, bool]:
    """The first *limit* bytes of a file and whether there was more."""
    proc = subprocess.Popen(["icat", *_offset(offset), path, inode], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, cwd="/tmp")
    watchdog = threading.Timer(timeout, proc.kill)  # a read that never ends is cut too
    watchdog.start()
    try:
        data = proc.stdout.read(limit + 1)
    finally:
        watchdog.cancel()
        proc.kill()
        _, err = proc.communicate()
    if not data and proc.returncode not in (0, -9):
        raise ArgumentError(f"icat failed: {_clip(err.decode('utf-8', 'replace').strip(), 2000)}")
    return data[:limit], len(data) > limit


@mcp.tool()
async def read_file(image: str, inode: str, offset: int = 0, max_bytes: int = 65536,
                    as_hex: bool = False, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The content of one file (also a deleted one, while its blocks are intact): up to
    max_bytes (1-1048576), as text (UTF-8, invalid bytes replaced) or as a hex dump (icat)."""
    try:
        path = _input_path(image, "image")
        limit = _int(max_bytes, "max_bytes", 1, MAX_READ, 65536)
        data, more = await asyncio.to_thread(
            _icat, path, _inode(inode), offset, limit,
            _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        if as_hex is True:
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{i:08x}  {chunk.hex(' '):<47}  {text}")
            content = "\n".join(lines)
        else:
            content = data.decode("utf-8", "replace")
        return {"image": path, "inode": inode, "bytes": len(data), "truncated": more,
                "content": content}
    except ArgumentError as exc:
        return _error(exc)


def _extract(path: str, inode: str, offset, target: str, timeout: int) -> int:
    with open(target, "xb") as handle:
        proc = subprocess.run(["icat", *_offset(offset), path, inode], stdout=handle,
                              stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, cwd="/tmp",
                              timeout=timeout)
    if proc.returncode != 0:
        os.unlink(target)
        raise ArgumentError(f"icat failed: {_clip(proc.stderr.decode('utf-8', 'replace'), 2000)}")
    return os.path.getsize(target)


@mcp.tool()
async def extract_file(image: str, inode: str, name: str, offset: int = 0,
                       timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Write one file's content to /out/<name> (a writable folder mounted at /out); an
    existing file is never overwritten. name: letters, digits, '.', '_', '-'."""
    try:
        path = _input_path(image, "image")
        if not isinstance(name, str) or not _NAME.match(name):
            raise ArgumentError("name: letters, digits, '.', '_' and '-' (no path)")
        if not (os.path.isdir("/out") and os.access("/out", os.W_OK)):
            raise ArgumentError("extract_file needs a writable folder mounted at /out")
        target = os.path.join("/out", name)
        if os.path.lexists(target):
            raise ArgumentError(f"/out/{name} exists already")
        size = await asyncio.to_thread(_extract, path, _inode(inode), offset, target,
                                       _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return {"image": path, "inode": inode, "written": target, "bytes": size}
    except (ArgumentError, OSError) as exc:
        return _error(exc)


@mcp.tool()
async def timeline(image: str, offset: int = 0, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """A MAC (modified, accessed, changed, born) timeline of all files, oldest first, in
    UTC (fls -r -m / | mactime)."""
    try:
        path = _input_path(image, "image")
        limit = _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT)
        body = await _tool(["fls", "-r", "-m", "/", *_offset(offset), path], limit)
        code, out, err = await asyncio.to_thread(
            _run, ["mactime", "-b", "-", "-d", "-z", "UTC"], limit, stdin=body.encode())
        if code != 0:
            raise ArgumentError(f"mactime failed (exit {code}): {_clip(err.strip(), 2000)}")
        return {"image": path, "timeline": _clip(out)}
    except ArgumentError as exc:
        return _error(exc)


if __name__ == "__main__":
    mcp.run("stdio")
