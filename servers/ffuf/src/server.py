#!/usr/bin/env python3
"""
FFUF MCP Server

A Model Context Protocol server that provides web fuzzing
capabilities using ffuf (Fuzz Faster U Fool).

Tools:
    - ffuf_dir: Directory/file discovery fuzzing
    - ffuf_vhost: Virtual host discovery
    - ffuf_param: Parameter fuzzing
    - ffuf_custom: Custom fuzzing with full control
    - get_fuzz_results: Retrieve previous fuzzing results
    - list_active_scans: Show running scans
    - list_wordlists: List available wordlists

axross-mcp-hub patch: every argument is validated before it reaches ffuf's command
line (an http(s) URL, header names and single-line values, method, extensions, status
codes, numbers); wordlists are the bundled SecLists files or files under /work (any
container path could be sent to the target before); stored results are bounded.
"""

import asyncio
import json
import logging
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ffuf-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    output_dir: str = Field(default="/tmp/ffuf-mcp", alias="FFUF_OUTPUT_DIR")
    wordlists_dir: str = Field(default="/opt/wordlists", alias="FFUF_WORDLISTS_DIR")
    default_timeout: int = Field(default=600, alias="FFUF_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="FFUF_MAX_CONCURRENT")
    default_threads: int = Field(default=40, alias="FFUF_THREADS")
    default_rate: int = Field(default=0, alias="FFUF_RATE")  # 0 = unlimited

    class Config:
        env_prefix = "FFUF_"


settings = Settings()


class FuzzResult(BaseModel):
    """Model for a single fuzz result."""

    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str | None = None
    redirect_location: str | None = None
    input_value: str | None = None
    position: int | None = None


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    fuzz_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    results: list[FuzzResult] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()

# Common wordlists (SecLists files bundled in the image)
WORDLISTS = {
    "common": "/opt/wordlists/common.txt",
    "raft-small-dirs": "/opt/wordlists/raft-small-directories.txt",
    "raft-small-files": "/opt/wordlists/raft-small-files.txt",
    "subdomains-top1mil": "/opt/wordlists/subdomains-top1million-5000.txt",
    "params-top": "/opt/wordlists/burp-parameter-names.txt",
}

# --- axross-mcp-hub: argument checks --------------------------------------------------
INPUT_ROOTS = tuple(p for p in os.environ.get("MCP_INPUT_ROOTS", "/work").split(":") if p)
MAX_STORED_RESULTS = 100
MAX_TIMEOUT = 3600
_URL = re.compile(r"^https?://[^\s]{1,2040}$")
_HEADER = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
_METHOD = re.compile(r"^[A-Z]{3,10}$")
_EXTENSION = re.compile(r"^\.?[A-Za-z0-9_-]{1,15}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


class ArgumentError(ValueError):
    """A tool argument that is not accepted; the text says why."""


def _url(value, need_fuzz: bool = True) -> str:
    if not isinstance(value, str) or not _URL.match(value):
        raise ArgumentError("url: an http:// or https:// URL without spaces")
    return value


def _int(value, name: str, low: int, high: int, default):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ArgumentError(f"{name}: an integer from {low} to {high}")
    return value


def _codes(value, name: str):
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 50 or not all(
            isinstance(c, int) and not isinstance(c, bool) and 100 <= c <= 599 for c in value):
        raise ArgumentError(f"{name}: a list of HTTP status codes (100-599)")
    return value


def _line(value, name: str, limit: int = 8192):
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > limit or any(c in value for c in "\r\n\x00"):
        raise ArgumentError(f"{name}: one line of at most {limit} characters")
    return value


def _headers(value):
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > 32:
        raise ArgumentError("headers: an object of at most 32 header names and values")
    for key, val in value.items():
        if not _HEADER.match(str(key)):
            raise ArgumentError(f"headers: {key!r} is not a header name")
        _line(val if isinstance(val, str) else None, f"headers {key}", 4096)
    return value


def _method(value) -> str:
    value = value or "GET"
    if not isinstance(value, str) or not _METHOD.match(value.upper()):
        raise ArgumentError("method: an HTTP method such as GET or POST")
    return value.upper()


def _extensions(value):
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 30 or not all(
            isinstance(e, str) and _EXTENSION.match(e) for e in value):
        raise ArgumentError("extensions: a list such as [\".php\", \".bak\"]")
    return value


def _wordlist(value) -> str:
    """A bundled wordlist name or a file under /work."""
    if isinstance(value, str) and value in WORDLISTS:
        return value
    roots = [os.path.realpath(r) for r in INPUT_ROOTS]
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise ArgumentError(f"wordlist: one of {', '.join(WORDLISTS)} or a file under /work")
    path = os.path.realpath(value if os.path.isabs(value) else os.path.join(roots[0], value))
    if not any(path.startswith(r.rstrip("/") + "/") for r in roots) or not os.path.isfile(path):
        raise ArgumentError(f"wordlist: one of {', '.join(WORDLISTS)} or a file under /work")
    return path


def _remember(store: dict, key: str, value, active: set) -> None:
    store[key] = value
    while len(store) > MAX_STORED_RESULTS:
        oldest = next(iter(store))
        if oldest in active:
            break
        del store[oldest]
# --------------------------------------------------------------------------------------


def parse_ffuf_json(output: str) -> list[FuzzResult]:
    """Parse ffuf JSON output."""
    results = []

    try:
        data = json.loads(output)
        for result in data.get("results", []):
            results.append(FuzzResult(
                url=result.get("url", ""),
                status=result.get("status", 0),
                length=result.get("length", 0),
                words=result.get("words", 0),
                lines=result.get("lines", 0),
                content_type=result.get("content-type"),
                redirect_location=result.get("redirectlocation"),
                input_value=result.get("input", {}).get("FUZZ"),
                position=result.get("position"),
            ))
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing ffuf output: {e}")

    return results


def get_wordlist_path(wordlist: str) -> str:
    """Get full path for a wordlist (a bundled name or a path checked by _wordlist)."""
    return WORDLISTS.get(wordlist, wordlist)


async def run_ffuf(
    url: str,
    wordlist: str,
    fuzz_type: str = "dir",
    extensions: list[str] | None = None,
    match_codes: list[int] | None = None,
    filter_codes: list[int] | None = None,
    filter_size: int | None = None,
    filter_words: int | None = None,
    threads: int | None = None,
    rate: int | None = None,
    timeout: int | None = None,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: str | None = None,
) -> ScanResult:
    """Execute ffuf fuzzing asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"ffuf_{scan_id}.json"

    result = ScanResult(
        scan_id=scan_id,
        target=url,
        fuzz_type=fuzz_type,
        started_at=datetime.now(),
    )
    _remember(scan_results, scan_id, result, active_scans)
    active_scans.add(scan_id)
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    # Build ffuf command
    wordlist_path = get_wordlist_path(wordlist)

    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist_path,
        "-o", str(output_file),
        "-of", "json",
        "-t", str(threads or settings.default_threads),
        "-noninteractive",
        "-s",  # Silent mode
    ]

    # Add rate limiting
    if rate or settings.default_rate:
        cmd.extend(["-rate", str(rate or settings.default_rate)])

    # Add extensions for directory fuzzing
    if extensions:
        cmd.extend(["-e", ",".join(extensions)])

    # Add match/filter codes
    if match_codes:
        cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])
    if filter_codes:
        cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])

    # Add size/word filters
    if filter_size is not None:
        cmd.extend(["-fs", str(filter_size)])
    if filter_words is not None:
        cmd.extend(["-fw", str(filter_words)])

    # Add HTTP method
    if method.upper() != "GET":
        cmd.extend(["-X", method.upper()])

    # Add POST data
    if data:
        cmd.extend(["-d", data])

    # Add custom headers
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    logger.info(f"Starting {fuzz_type} fuzzing {scan_id} for target: {url}")
    logger.debug(f"Command: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout or settings.default_timeout),
        )

        result.completed_at = datetime.now()

        # Read output file
        if output_file.exists():
            output_content = output_file.read_text()
            result.raw_output = output_content
            result.results = parse_ffuf_json(output_content)

        # Generate stats
        status_counts = {}
        for r in result.results:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1

        result.stats = {
            "total_results": len(result.results),
            "by_status": status_counts,
            "wordlist": wordlist,
        }

        if process.returncode == 0:
            result.status = "completed"
            logger.info(f"Fuzzing {scan_id} completed: {len(result.results)} results")
        else:
            stderr_text = stderr.decode()
            if result.results:
                result.status = "completed"
            else:
                result.status = "failed"
                result.error = stderr_text
                logger.error(f"Fuzzing {scan_id} failed: {stderr_text}")

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Fuzzing timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Fuzzing {scan_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Fuzzing {scan_id} error: {e}")

    finally:
        active_scans.discard(scan_id)

    return result


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    results_summary = []
    for r in result.results[:100]:  # Limit to 100
        results_summary.append({
            "url": r.url,
            "status": r.status,
            "length": r.length,
            "words": r.words,
            "input": r.input_value,
        })

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "fuzz_type": result.fuzz_type,
        "status": result.status,
        "stats": result.stats,
        "results": results_summary,
        "error": result.error,
    }


# Create MCP server
app = Server("ffuf-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="ffuf_dir",
            description="Directory and file discovery fuzzing. "
            "Discovers hidden directories, files, and endpoints on web servers.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                        "default": "common",
                    },
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions to append (e.g., php, html, txt)",
                    },
                    "filter_codes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "HTTP status codes to filter out (e.g., 404, 403)",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="ffuf_vhost",
            description="Virtual host discovery. "
            "Discovers subdomains and virtual hosts by fuzzing the Host header.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g., https://10.10.10.10)",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Base domain for vhost discovery (e.g., example.com)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Subdomain wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                        "default": "subdomains-top1mil",
                    },
                    "filter_size": {
                        "type": "integer",
                        "description": "Filter responses by size (to remove default page)",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url", "domain"],
            },
        ),
        Tool(
            name="ffuf_param",
            description="Parameter fuzzing. "
            "Discovers hidden GET or POST parameters.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with FUZZ keyword (e.g., https://example.com/page?FUZZ=test)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Parameter wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                        "default": "params-top",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST"],
                        "description": "HTTP method",
                        "default": "GET",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data with FUZZ keyword (e.g., FUZZ=test)",
                    },
                    "filter_size": {
                        "type": "integer",
                        "description": "Filter responses by size",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads",
                        "default": 40,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="ffuf_custom",
            description="Custom fuzzing with full control over all options. "
            "Use FUZZ keyword in URL, headers, or data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (use FUZZ keyword where needed)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, PUT, etc.)",
                        "default": "GET",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Custom headers as key-value pairs",
                    },
                    "data": {
                        "type": "string",
                        "description": "Request body data",
                    },
                    "match_codes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Only show these HTTP status codes",
                    },
                    "filter_codes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Hide these HTTP status codes",
                    },
                    "filter_size": {
                        "type": "integer",
                        "description": "Filter by response size",
                    },
                    "filter_words": {
                        "type": "integer",
                        "description": "Filter by word count",
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Concurrent threads",
                        "default": 40,
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Rate limit (requests per second)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["url", "wordlist"],
            },
        ),
        Tool(
            name="list_wordlists",
            description="List available wordlists for fuzzing.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="get_fuzz_results",
            description="Retrieve results from a previous fuzzing session by scan ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID returned from a previous scan",
                    },
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_active_scans",
            description="List currently running fuzzing sessions.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "ffuf_dir":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            url = _url(arguments.get("url"))
            if "FUZZ" not in url:
                url = url.rstrip("/") + "/FUZZ"

            result = await run_ffuf(
                url=url,
                wordlist=_wordlist(arguments.get("wordlist", "common")),
                fuzz_type="directory",
                extensions=_extensions(arguments.get("extensions")),
                filter_codes=_codes(arguments.get("filter_codes", [404]), "filter_codes"),
                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "ffuf_vhost":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            domain = arguments.get("domain")
            if not isinstance(domain, str) or not _DOMAIN.match(domain):
                raise ArgumentError("domain: a domain name such as example.com")
            headers = {"Host": f"FUZZ.{domain}"}

            result = await run_ffuf(
                url=_url(arguments.get("url")),
                wordlist=_wordlist(arguments.get("wordlist", "subdomains-top1mil")),
                fuzz_type="vhost",
                headers=headers,
                filter_size=_int(arguments.get("filter_size"), "filter_size", 0, 1 << 40, None),
                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "ffuf_param":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_ffuf(
                url=_url(arguments.get("url")),
                wordlist=_wordlist(arguments.get("wordlist", "params-top")),
                fuzz_type="parameter",
                method=_method(arguments.get("method", "GET")),
                data=_line(arguments.get("data"), "data"),
                filter_size=_int(arguments.get("filter_size"), "filter_size", 0, 1 << 40, None),
                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "ffuf_custom":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_ffuf(
                url=_url(arguments.get("url")),
                wordlist=_wordlist(arguments.get("wordlist")),
                fuzz_type="custom",
                method=_method(arguments.get("method", "GET")),
                headers=_headers(arguments.get("headers")),
                data=_line(arguments.get("data"), "data"),
                match_codes=_codes(arguments.get("match_codes"), "match_codes"),
                filter_codes=_codes(arguments.get("filter_codes"), "filter_codes"),
                filter_size=_int(arguments.get("filter_size"), "filter_size", 0, 1 << 40, None),
                filter_words=_int(arguments.get("filter_words"), "filter_words", 0, 1 << 30, None),
                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
                rate=_int(arguments.get("rate"), "rate", 0, 10000, None),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "list_wordlists":
            available = {}
            for name_key, path in WORDLISTS.items():
                exists = Path(path).exists()
                available[name_key] = {
                    "path": path,
                    "available": exists,
                }

            # Also list files in wordlists directory
            custom = []
            wordlist_path = Path(settings.wordlists_dir)
            if wordlist_path.exists():
                for f in wordlist_path.rglob("*.txt"):
                    custom.append(str(f.relative_to(wordlist_path)))

            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "builtin_wordlists": available,
                        "custom_wordlists": custom[:50],
                        "wordlists_directory": settings.wordlists_dir,
                    }, indent=2),
                )
            ]

        elif name == "get_fuzz_results":
            scan_id = str(arguments.get("scan_id", ""))
            result = scan_results.get(scan_id)

            if result:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(format_scan_summary(result), indent=2),
                    )
                ]
            else:
                return [
                    TextContent(type="text", text=f"Scan '{scan_id}' not found")
                ]

        elif name == "list_active_scans":
            active = [
                {
                    "scan_id": scan_id,
                    "target": scan_results[scan_id].target,
                    "fuzz_type": scan_results[scan_id].fuzz_type,
                    "started_at": scan_results[scan_id].started_at.isoformat(),
                }
                for scan_id in active_scans
                if scan_id in scan_results
            ]

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "active_scans": active,
                            "count": len(active),
                            "max_concurrent": settings.max_concurrent_scans,
                        },
                        indent=2,
                    ),
                )
            ]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except ArgumentError as e:
        return [TextContent(type="text", text=f"Error: {e}")]
    except Exception as e:
        logger.exception(f"Error executing tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available resources."""
    resources = []

    for scan_id, result in scan_results.items():
        if result.status == "completed":
            result_count = len(result.results)
            resources.append(
                Resource(
                    uri=f"ffuf://results/{scan_id}",
                    name=f"Fuzz Results: {result.target} ({result_count} results)",
                    description=f"{result.fuzz_type} fuzzing completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("ffuf://results/"):
        scan_id = uri.replace("ffuf://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting FFUF MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")
    logger.info(f"Wordlists directory: {settings.wordlists_dir}")

    # Ensure directories exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.wordlists_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
