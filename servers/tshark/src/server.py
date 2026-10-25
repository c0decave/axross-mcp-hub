#!/usr/bin/env python3
"""tshark MCP server (axross-mcp-hub): read packet captures with Wireshark's tshark.

Tools:
    - pcap_info: file statistics (capinfos)
    - protocol_hierarchy: protocols by frames and bytes (-z io,phs)
    - conversations / endpoints: who talks to whom (-z conv / -z endpoints)
    - packets: packet summaries or chosen fields, with a display filter
    - follow_stream: the payload of one TCP/UDP/TLS/HTTP stream (-z follow)
    - http_requests / dns_queries: the requests and queries in a capture
    - credentials: credentials tshark recognises in clear text protocols (-z credentials)

Captures are read only from /work (the folder axross mounts). tshark reads files only
(-r), never captures, and never resolves names (-n). Every argument is validated; the
display filter is passed as the value of -Y, so it can never become an option. Nothing
runs through a shell.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("tshark-mcp")

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

TSHARK = "tshark"
CAPINFOS = "capinfos"
_FIELD = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,99}$")
CONV_TYPES = ("eth", "ip", "ipv6", "tcp", "udp", "sctp", "wlan")
FOLLOW_TYPES = ("tcp", "udp", "tls", "http", "http2", "quic")
FOLLOW_MODES = ("ascii", "hex", "raw")
DEFAULT_TIMEOUT = 120

mcp = FastMCP("tshark-mcp")


def _filter(value) -> str:
    return _line(value, "display_filter", 2000)


async def _tshark(args: list[str], timeout: int) -> str:
    code, out, err = await asyncio.to_thread(_run, [TSHARK, "-n", *args], timeout)
    if code != 0:
        raise ArgumentError(f"tshark failed (exit {code}): {_clip(err.strip(), 2000)}")
    return _clip(out)


def _error(exc: Exception) -> dict:
    return {"error": str(exc)}


@mcp.tool()
async def pcap_info(pcap: str) -> dict:
    """File statistics of a capture: format, encapsulation, packet count, duration,
    data rates, hashes (capinfos). pcap: a file under /work."""
    try:
        path = _input_path(pcap, "pcap")
        code, out, err = await asyncio.to_thread(_run, [CAPINFOS, "-M", path], DEFAULT_TIMEOUT)
        if code != 0:
            raise ArgumentError(f"capinfos failed (exit {code}): {_clip(err.strip(), 2000)}")
        return {"pcap": path, "capinfos": _clip(out)}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def protocol_hierarchy(pcap: str, display_filter: str = "", timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The protocol hierarchy of a capture (frames and bytes per protocol), optionally
    only for packets matching a Wireshark display filter."""
    try:
        path = _input_path(pcap, "pcap")
        flt = _filter(display_filter)
        tap = "io,phs" + (f",{flt}" if flt else "")
        out = await _tshark(["-r", path, "-q", "-z", tap], _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return {"pcap": path, "protocol_hierarchy": out}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def conversations(pcap: str, kind: str = "tcp", display_filter: str = "",
                        timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Conversations of a capture: kind is one of eth, ip, ipv6, tcp, udp, sctp, wlan."""
    try:
        path = _input_path(pcap, "pcap")
        if kind not in CONV_TYPES:
            raise ArgumentError(f"kind: one of {', '.join(CONV_TYPES)}")
        flt = _filter(display_filter)
        tap = f"conv,{kind}" + (f",{flt}" if flt else "")
        out = await _tshark(["-r", path, "-q", "-z", tap], _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return {"pcap": path, "conversations": out}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def endpoints(pcap: str, kind: str = "ip", display_filter: str = "",
                    timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Endpoints of a capture with packet and byte counts: kind as for conversations."""
    try:
        path = _input_path(pcap, "pcap")
        if kind not in CONV_TYPES:
            raise ArgumentError(f"kind: one of {', '.join(CONV_TYPES)}")
        flt = _filter(display_filter)
        tap = f"endpoints,{kind}" + (f",{flt}" if flt else "")
        out = await _tshark(["-r", path, "-q", "-z", tap], _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return {"pcap": path, "endpoints": out}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def packets(pcap: str, display_filter: str = "", fields: list[str] | None = None,
                  max_packets: int = 100, verbose: bool = False,
                  timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Packets of a capture: one summary line each, the given fields (e.g. ["frame.number",
    "ip.src", "tcp.dstport", "http.host"]) as tab-separated columns, or with verbose the
    full dissection (-V). display_filter: a Wireshark display filter; max_packets 1-10000."""
    try:
        path = _input_path(pcap, "pcap")
        flt = _filter(display_filter)
        count = _int(max_packets, "max_packets", 1, 10000, 100)
        args = ["-r", path, "-c", str(count)]
        if flt:
            args += ["-Y", flt]
        if fields:
            if not isinstance(fields, list) or len(fields) > 40 or not all(
                    isinstance(f, str) and _FIELD.match(f) for f in fields):
                raise ArgumentError("fields: up to 40 Wireshark field names such as ip.src")
            args += ["-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "occurrence=a"]
            for field in fields:
                args += ["-e", field]
        elif verbose is True:
            args.append("-V")
        out = await _tshark(args, _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return {"pcap": path, "packets": out}
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def follow_stream(pcap: str, stream: int, protocol: str = "tcp", mode: str = "ascii",
                        timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The payload of one stream, as Wireshark's Follow Stream shows it. stream: the stream
    index (tcp.stream / udp.stream, see conversations or packets); protocol: tcp, udp, tls,
    http, http2, quic; mode: ascii, hex or raw."""
    try:
        path = _input_path(pcap, "pcap")
        index = _int(stream, "stream", 0, 10_000_000, 0)
        if protocol not in FOLLOW_TYPES:
            raise ArgumentError(f"protocol: one of {', '.join(FOLLOW_TYPES)}")
        if mode not in FOLLOW_MODES:
            raise ArgumentError(f"mode: one of {', '.join(FOLLOW_MODES)}")
        out = await _tshark(["-r", path, "-q", "-z", f"follow,{protocol},{mode},{index}"],
                            _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return {"pcap": path, "stream": index, "follow": out}
    except ArgumentError as exc:
        return _error(exc)


async def _fields(pcap, flt: str, fields: list[str], max_packets, timeout) -> dict:
    path = _input_path(pcap, "pcap")
    count = _int(max_packets, "max_packets", 1, 100000, 1000)
    args = ["-r", path, "-Y", flt, "-T", "fields", "-E", "header=y", "-E", "separator=/t"]
    for field in fields:
        args += ["-e", field]
    out = await _tshark(args, _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
    lines = out.splitlines()
    return {"pcap": path, "rows": len(lines) - 1 if lines else 0,
            "table": "\n".join(lines[: count + 1])}


@mcp.tool()
async def http_requests(pcap: str, max_packets: int = 1000, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The HTTP requests of a capture: frame, source, destination, method, host, URI,
    user agent (plain HTTP only; TLS is not decrypted)."""
    try:
        return await _fields(pcap, "http.request", [
            "frame.number", "ip.src", "ip.dst", "tcp.dstport", "http.request.method",
            "http.host", "http.request.uri", "http.user_agent"], max_packets, timeout)
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def dns_queries(pcap: str, max_packets: int = 1000, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """The DNS queries and answers of a capture: frame, client, server, name, type,
    response flag, answers."""
    try:
        return await _fields(pcap, "dns", [
            "frame.number", "ip.src", "ip.dst", "dns.qry.name", "dns.qry.type",
            "dns.flags.response", "dns.a", "dns.aaaa", "dns.cname"], max_packets, timeout)
    except ArgumentError as exc:
        return _error(exc)


@mcp.tool()
async def credentials(pcap: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Credentials tshark recognises in the capture (HTTP basic auth, FTP, POP, IMAP,
    SMTP, ... in clear text): -z credentials."""
    try:
        path = _input_path(pcap, "pcap")
        out = await _tshark(["-r", path, "-q", "-z", "credentials"],
                            _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return {"pcap": path, "credentials": out}
    except ArgumentError as exc:
        return _error(exc)


if __name__ == "__main__":
    mcp.run("stdio")
