#!/usr/bin/env python3
"""
Binwalk MCP Server

A Model Context Protocol server that provides firmware analysis
capabilities using binwalk.

Tools:
    - binwalk_scan: Scan firmware for embedded files and signatures
    - binwalk_extract: Extract embedded files and filesystems
    - binwalk_entropy: Analyze entropy to detect compression/encryption
    - binwalk_hexdump: Display hex dump of file sections
    - list_extractions: List completed extractions
    - get_scan_results: Retrieve results from a previous scan

axross-mcp-hub patch: files are read only from /work (the folder axross mounts),
every path is resolved and passed as an absolute path (never an option), numbers
are range-checked, extraction goes to /out when a writable folder is mounted
there (else /tmp, 64 MiB), the entropy scan does not try to plot, and stored
results are bounded.
"""

import asyncio
import json
import logging
import os
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
logger = logging.getLogger("binwalk-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    output_dir: str = Field(default="/tmp/binwalk-mcp", alias="BINWALK_OUTPUT_DIR")
    default_timeout: int = Field(default=300, alias="BINWALK_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="BINWALK_MAX_CONCURRENT")
    max_file_size: int = Field(default=104857600, alias="BINWALK_MAX_FILE_SIZE")  # 100MB

    class Config:
        env_prefix = "BINWALK_"


settings = Settings()


class SignatureMatch(BaseModel):
    """Model for a signature match."""

    offset: int
    offset_hex: str
    description: str
    size: int | None = None


class EntropyBlock(BaseModel):
    """Model for entropy analysis block."""

    offset: int
    entropy: float
    description: str | None = None


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    filename: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    signatures: list[SignatureMatch] = []
    entropy_data: list[EntropyBlock] = []
    extraction_path: str | None = None
    extracted_files: list[str] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()


# --- axross-mcp-hub: argument checks --------------------------------------------------
#: Input files are read only from these folders (axross mounts the user's folder at /work).
INPUT_ROOTS = tuple(p for p in os.environ.get("MCP_INPUT_ROOTS", "/work").split(":") if p)
#: Results kept in memory (the oldest are dropped).
MAX_STORED_RESULTS = 100
MAX_TIMEOUT = 3600


class ArgumentError(ValueError):
    """A tool argument that is not accepted; the text says why."""


def _input_path(value, what: str = "filepath", *, kind: str = "file") -> str:
    """*value* as an absolute, symlink-free path under INPUT_ROOTS (relative paths are
    taken from the first root). The result starts with "/", so it can never become an
    option of the tool it is passed to. *kind*: file, dir or any."""
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


def _int(value, name: str, low: int, high: int, default):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ArgumentError(f"{name}: an integer from {low} to {high}")
    return value


def _remember(store: dict, key: str, value, active: set) -> None:
    store[key] = value
    while len(store) > MAX_STORED_RESULTS:
        oldest = next(iter(store))
        if oldest in active:
            break
        del store[oldest]
# --------------------------------------------------------------------------------------


def _extraction_base() -> Path:
    """/out when the user mounted a writable folder there, else the output dir."""
    out = Path("/out")
    if out.is_dir() and os.access(out, os.W_OK):
        return out
    return Path(settings.output_dir)


def parse_binwalk_output(output: str) -> list[SignatureMatch]:
    """Parse binwalk signature scan output."""
    signatures = []

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("DECIMAL") or line.startswith("-"):
            continue

        parts = line.split(None, 2)
        if len(parts) >= 3:
            try:
                decimal_offset = int(parts[0])
                hex_offset = parts[1]
                description = parts[2] if len(parts) > 2 else ""

                signatures.append(SignatureMatch(
                    offset=decimal_offset,
                    offset_hex=hex_offset,
                    description=description,
                ))
            except (ValueError, IndexError):
                continue

    return signatures


def parse_entropy_output(output: str) -> list[EntropyBlock]:
    """Parse binwalk entropy analysis output."""
    entropy_data = []

    for line in output.strip().split("\n"):
        if "Rising entropy edge" in line or "Falling entropy edge" in line:
            parts = line.split()
            try:
                offset = int(parts[0])
                entropy_data.append(EntropyBlock(
                    offset=offset,
                    entropy=0.0,
                    description=line,
                ))
            except (ValueError, IndexError):
                continue

    return entropy_data


def list_extracted_files(extraction_dir: Path, max_files: int = 100) -> list[str]:
    """List files in extraction directory."""
    files = []
    if extraction_dir.exists():
        for path in extraction_dir.rglob("*"):
            if path.is_file():
                files.append(str(path.relative_to(extraction_dir)))
                if len(files) >= max_files:
                    break
    return files


async def run_binwalk_scan(
    filepath: str,
    scan_type: str = "signature",
    extract: bool = False,
    timeout: int | None = None,
) -> ScanResult:
    """Execute a binwalk scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    filename = Path(filepath).name

    result = ScanResult(
        scan_id=scan_id,
        filename=filename,
        scan_type=scan_type,
        started_at=datetime.now(),
    )
    _remember(scan_results, scan_id, result, active_scans)
    active_scans.add(scan_id)

    # Build binwalk command based on scan type
    extraction_dir = _extraction_base() / f"extract_{scan_id}"

    if scan_type == "signature":
        cmd = ["binwalk", filepath]
    elif scan_type == "extract":
        cmd = ["binwalk", "-e", "-C", str(extraction_dir), filepath]
        if os.geteuid() == 0:
            # axross runs the container as its (rootless, capability-free) root when a
            # folder is mounted; binwalk refuses to extract as root without this.
            cmd[1:1] = ["--run-as=root"]
        result.extraction_path = str(extraction_dir)
    elif scan_type == "entropy":
        cmd = ["binwalk", "-E", "-N", filepath]  # -N: no plot window
    elif scan_type == "hexdump":
        cmd = ["binwalk", "-W", filepath]
    else:
        cmd = ["binwalk", filepath]

    logger.info(f"Starting {scan_type} scan {scan_id} for file: {filename}")
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
        stdout_text = stdout.decode()
        result.raw_output = stdout_text

        # Parse output based on scan type
        if scan_type == "signature":
            result.signatures = parse_binwalk_output(stdout_text)
            result.stats = {
                "total_signatures": len(result.signatures),
                "file_types": list(set(
                    s.description.split(",")[0].strip()
                    for s in result.signatures
                    if s.description
                ))[:10],
            }
        elif scan_type == "extract":
            result.signatures = parse_binwalk_output(stdout_text)
            result.extracted_files = list_extracted_files(extraction_dir)
            result.stats = {
                "total_signatures": len(result.signatures),
                "extracted_files": len(result.extracted_files),
                "extraction_path": str(extraction_dir),
            }
        elif scan_type == "entropy":
            result.entropy_data = parse_entropy_output(stdout_text)
            result.stats = {
                "entropy_edges": len(result.entropy_data),
            }

        if process.returncode == 0:
            result.status = "completed"
            logger.info(f"Scan {scan_id} completed successfully")
        else:
            stderr_text = stderr.decode()
            if stderr_text and "error" in stderr_text.lower():
                result.status = "failed"
                result.error = stderr_text
                logger.error(f"Scan {scan_id} failed: {stderr_text}")
            else:
                result.status = "completed"

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Scan {scan_id} error: {e}")

    finally:
        active_scans.discard(scan_id)

    return result


async def get_hexdump(
    filepath: str,
    offset: int = 0,
    length: int = 256,
) -> str:
    """Get hexdump of file section."""
    cmd = ["xxd", "-s", str(offset), "-l", str(length), filepath]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await asyncio.wait_for(
            process.communicate(),
            timeout=30.0,
        )

        return stdout.decode()

    except Exception as e:
        return f"Error getting hexdump: {e}"


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    signatures_summary = []
    for sig in result.signatures[:50]:  # Limit to 50
        signatures_summary.append({
            "offset": sig.offset,
            "offset_hex": sig.offset_hex,
            "description": sig.description[:200] if sig.description else None,
        })

    return {
        "scan_id": result.scan_id,
        "filename": result.filename,
        "scan_type": result.scan_type,
        "status": result.status,
        "stats": result.stats,
        "signatures": signatures_summary,
        "extraction_path": result.extraction_path,
        "extracted_files": result.extracted_files[:50],
        "error": result.error,
    }


# Create MCP server
app = Server("binwalk-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="binwalk_scan",
            description="Scan a firmware file for embedded files, filesystems, and signatures. "
            "Identifies compressed archives, filesystems, bootloaders, and more.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the firmware file to scan",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="binwalk_extract",
            description="Extract embedded files and filesystems from firmware. "
            "Recursively extracts archives, SquashFS, JFFS2, CPIO, and more.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the firmware file to extract",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Extraction timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="binwalk_entropy",
            description="Analyze file entropy to detect compressed or encrypted sections. "
            "High entropy regions often indicate encryption or compression.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the file to analyze",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Analysis timeout in seconds",
                        "default": 120,
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="binwalk_hexdump",
            description="Display hex dump of a file section. Useful for examining "
            "specific offsets found during signature scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the file",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Starting offset in bytes",
                        "default": 0,
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to display",
                        "default": 256,
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="get_scan_results",
            description="Retrieve results from a previous scan by scan ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID returned from a previous scan",
                    },
                    "include_raw": {
                        "type": "boolean",
                        "description": "Include raw binwalk output",
                        "default": False,
                    },
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_extractions",
            description="List all completed extractions with their file contents.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="list_active_scans",
            description="List currently running scans.",
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
        if name == "binwalk_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            filepath = _input_path(arguments.get("filepath"))

            result = await run_binwalk_scan(
                filepath=filepath,
                scan_type="signature",
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "binwalk_extract":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            filepath = _input_path(arguments.get("filepath"))

            result = await run_binwalk_scan(
                filepath=filepath,
                scan_type="extract",
                extract=True,
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, 600),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "binwalk_entropy":
            filepath = _input_path(arguments.get("filepath"))

            result = await run_binwalk_scan(
                filepath=filepath,
                scan_type="entropy",
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, 120),
            )

            output = format_scan_summary(result)
            if result.raw_output:
                output["entropy_analysis"] = result.raw_output[:5000]

            return [
                TextContent(
                    type="text",
                    text=json.dumps(output, indent=2),
                )
            ]

        elif name == "binwalk_hexdump":
            filepath = _input_path(arguments.get("filepath"))

            offset = _int(arguments.get("offset"), "offset", 0, 2**62, 0)
            length = _int(arguments.get("length"), "length", 1, 4096, 256)  # Max 4KB

            hexdump = await get_hexdump(filepath, offset, length)

            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "filepath": filepath,
                        "offset": offset,
                        "length": length,
                        "hexdump": hexdump,
                    }, indent=2),
                )
            ]

        elif name == "get_scan_results":
            scan_id = str(arguments.get("scan_id", ""))
            result = scan_results.get(scan_id)

            if result:
                output = format_scan_summary(result)
                if arguments.get("include_raw") and result.raw_output:
                    output["raw_output"] = result.raw_output[:10000]
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(output, indent=2),
                    )
                ]
            else:
                return [
                    TextContent(type="text", text=f"Scan '{scan_id}' not found")
                ]

        elif name == "list_extractions":
            extractions = []
            for scan_id, result in scan_results.items():
                if result.scan_type == "extract" and result.status == "completed":
                    extractions.append({
                        "scan_id": scan_id,
                        "filename": result.filename,
                        "extraction_path": result.extraction_path,
                        "extracted_files_count": len(result.extracted_files),
                        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                    })

            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "extractions": extractions,
                        "count": len(extractions),
                    }, indent=2),
                )
            ]

        elif name == "list_active_scans":
            active = [
                {
                    "scan_id": scan_id,
                    "filename": scan_results[scan_id].filename,
                    "scan_type": scan_results[scan_id].scan_type,
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
            sig_count = len(result.signatures)
            resources.append(
                Resource(
                    uri=f"binwalk://results/{scan_id}",
                    name=f"Scan Results: {result.filename} ({sig_count} signatures)",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("binwalk://results/"):
        scan_id = uri.replace("binwalk://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting Binwalk MCP Server")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure directories exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
