#!/usr/bin/env python3
"""MCP server for reading file metadata using ExifTool.

axross-mcp-hub patch (upstream: joshmsimpson/exiftool_mcp): read-only. Files are read
only from /work (the folder axross mounts) and passed as absolute paths; requested tags
filter exiftool's JSON in Python instead of becoming "-TAG" arguments (a "tag" such as
"if" became exiftool's -if option, which evaluates Perl); write_metadata and
remove_metadata are not offered (they changed the user's files and passed tag names and
values as exiftool arguments). Output is size-bounded.
"""

import asyncio
import fnmatch
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("exiftool-mcp")

# Initialize MCP server
app = Server("exiftool-mcp")

#: axross-mcp-hub: files are read only from these folders (axross mounts /work).
INPUT_ROOTS = tuple(p for p in os.environ.get("MCP_INPUT_ROOTS", "/work").split(":") if p)
MAX_OUTPUT = 200_000
TIMEOUT = 120


def _input_path(value) -> Path:
    """*value* as an absolute, symlink-free path of a file under INPUT_ROOTS, or ValueError."""
    roots = [os.path.realpath(r) for r in INPUT_ROOTS]
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 4096:
        raise ValueError(f"file_path: a path under {', '.join(INPUT_ROOTS)}")
    path = os.path.realpath(value if os.path.isabs(value) else os.path.join(roots[0], value))
    if not any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots):
        raise ValueError(f"file_path: only files under {', '.join(INPUT_ROOTS)} are read "
                         "(mount the folder there)")
    if not os.path.isfile(path):
        raise ValueError(f"File not found: {value}")
    return Path(path)


def check_exiftool_installed() -> bool:
    """Check if exiftool is installed and available in PATH."""
    return shutil.which("exiftool") is not None


async def run_exiftool(args: list[str]) -> tuple[str, str, int]:
    """Run exiftool command and return stdout, stderr, and return code."""
    try:
        process = await asyncio.create_subprocess_exec(
            "exiftool",
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return "", f"exiftool did not finish within {TIMEOUT} s", 1
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            process.returncode or 0,
        )
    except FileNotFoundError:
        return "", "exiftool not found in PATH", 1


def _select(metadata: dict, tags: list[str]) -> dict:
    """The entries of *metadata* whose key ("Group:Tag") or tag name matches one of *tags*
    (case-insensitive, * and ? as wildcards)."""
    patterns = [t.lower() for t in tags]
    out = {}
    for key, value in metadata.items():
        name = key.split(":", 1)[-1].lower()
        if key == "SourceFile" or any(fnmatch.fnmatchcase(key.lower(), p) or
                                      fnmatch.fnmatchcase(name, p) for p in patterns):
            out[key] = value
    return out


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available ExifTool tools."""
    return [
        Tool(
            name="read_metadata",
            description="Read metadata from a file using ExifTool. Supports images, videos, audio files, PDFs, and many other formats. Returns detailed metadata including EXIF, IPTC, XMP, and format-specific information. Files are read from /work.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file under /work (absolute, or relative to /work)",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: Specific metadata tags to return (e.g., ['DateTimeOriginal', 'Make', 'GPS*']). If not specified, all metadata is returned.",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_supported_formats",
            description="List all file formats supported by ExifTool for metadata extraction.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls for ExifTool operations."""

    # Check if exiftool is installed
    if not check_exiftool_installed():
        return [
            TextContent(
                type="text",
                text="Error: exiftool is not installed or not found in PATH. Please install ExifTool from https://exiftool.org/",
            )
        ]

    arguments = arguments if isinstance(arguments, dict) else {}

    if name == "read_metadata":
        tags = arguments.get("tags") or []
        if not isinstance(tags, list) or len(tags) > 200 or not all(
                isinstance(t, str) and 0 < len(t) <= 100 for t in tags):
            return [TextContent(type="text", text="Error: tags must be a list of tag names")]

        # Validate the path: a file under /work
        try:
            path = _input_path(arguments.get("file_path"))
        except ValueError as exc:
            return [TextContent(type="text", text=f"Error: {exc}")]

        # Build exiftool command: fixed options, the file last (an absolute path)
        args = ["-json", "-a", "-G1", str(path)]

        # Run exiftool
        stdout, stderr, returncode = await run_exiftool(args)

        if returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error running exiftool: {stderr[:4000]}",
                )
            ]

        try:
            # Parse JSON output
            metadata = json.loads(stdout)

            # Format output nicely
            if metadata and len(metadata) > 0:
                selected = _select(metadata[0], tags) if tags else metadata[0]
                formatted = json.dumps(selected, indent=2)
                if len(formatted) > MAX_OUTPUT:
                    formatted = formatted[:MAX_OUTPUT] + "\n[... cut]"
                return [
                    TextContent(
                        type="text",
                        text=f"Metadata for {path.name}:\n\n{formatted}",
                    )
                ]
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"No metadata found for {path.name}",
                    )
                ]
        except json.JSONDecodeError as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error parsing exiftool output: {e}\n\nRaw output:\n{stdout[:4000]}",
                )
            ]

    elif name == "list_supported_formats":
        # Run exiftool -listf to get readable formats
        stdout, stderr, returncode = await run_exiftool(["-listf"])

        if returncode != 0:
            return [
                TextContent(
                    type="text",
                    text=f"Error running exiftool: {stderr}",
                )
            ]

        return [
            TextContent(
                type="text",
                text=f"ExifTool Supported File Formats:\n\n{stdout}",
            )
        ]

    else:
        return [
            TextContent(
                type="text",
                text=f"Error: Unknown tool: {name}",
            )
        ]


async def main():
    """Run the MCP server."""
    from mcp.server.stdio import stdio_server

    logger.info("Starting MCP ExifTool server")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
