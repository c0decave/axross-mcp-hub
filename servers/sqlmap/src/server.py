#!/usr/bin/env python3
"""
SQLMap MCP Server

A Model Context Protocol server that provides SQL injection detection
and exploitation capabilities using SQLMap.

Tools:
    - sql_scan: Scan URL for SQL injection vulnerabilities
    - sql_enumerate: Enumerate databases, tables, columns
    - sql_dump: Dump data from database
    - sql_test: Test specific parameters for injection
    - get_scan_results: Retrieve previous scan results

axross-mcp-hub patch: every argument is validated before it reaches sqlmap's
command line (an http(s) URL, names of parameters, databases, tables and
columns, single-line data and cookie values, level 1-5, risk 1-3); sqlmap runs
with this server's own Python interpreter; stored results are bounded.
"""

import asyncio
import json
import logging
import os
import re
import sys
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
logger = logging.getLogger("sqlmap-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    sqlmap_path: str = Field(default="/opt/sqlmap/sqlmap.py", alias="SQLMAP_PATH")
    output_dir: str = Field(default="/tmp/sqlmap-mcp", alias="SQLMAP_OUTPUT_DIR")
    default_timeout: int = Field(default=300, alias="SQLMAP_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="SQLMAP_MAX_CONCURRENT")
    default_level: int = Field(default=1, alias="SQLMAP_LEVEL")
    default_risk: int = Field(default=1, alias="SQLMAP_RISK")

    class Config:
        env_prefix = "SQLMAP_"


settings = Settings()


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    vulnerabilities: list[dict[str, Any]] = []
    data: dict[str, Any] = {}
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


_URL = re.compile(r"^https?://[^\s]{1,2040}$")
_NAME = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.\-]{0,127}$")
_NAMES = re.compile(r"^[A-Za-z0-9_$\[\]][A-Za-z0-9_$.\-\[\],]{0,511}$")


def _url(value) -> str:
    if not isinstance(value, str) or not _URL.match(value):
        raise ArgumentError("target: an http:// or https:// URL without spaces")
    return value


def _name(value, what: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _NAME.match(value):
        raise ArgumentError(f"{what}: letters, digits, '_', '$', '.' and '-'")
    return value


def _param_names(value) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _NAMES.match(value):
        raise ArgumentError("params: parameter names separated by ','")
    return value


def _line(value, what: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > 8192 or any(c in value for c in "\r\n\x00"):
        raise ArgumentError(f"{what}: one line of text (at most 8192 characters)")
    return value


def _columns(value) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 256:
        raise ArgumentError("columns: a list of column names")
    return [_name(v, "columns") for v in value]


def parse_sqlmap_output(output: str) -> dict[str, Any]:
    """Parse sqlmap output for key findings."""
    findings = {
        "injectable_params": [],
        "dbms": None,
        "databases": [],
        "tables": [],
        "columns": [],
        "data": [],
    }

    # Extract injectable parameters
    param_matches = re.findall(
        r"Parameter: ([^\s]+) \((.*?)\)", output, re.IGNORECASE
    )
    for param, injection_type in param_matches:
        findings["injectable_params"].append({
            "parameter": param,
            "type": injection_type,
        })

    # Extract DBMS
    dbms_match = re.search(
        r"back-end DBMS: (.+)", output, re.IGNORECASE
    )
    if dbms_match:
        findings["dbms"] = dbms_match.group(1).strip()

    # Extract databases
    db_section = re.search(
        r"available databases \[\d+\]:(.+?)(?=\n\n|\Z)", output, re.DOTALL
    )
    if db_section:
        findings["databases"] = [
            db.strip().strip("[*] ")
            for db in db_section.group(1).strip().split("\n")
            if db.strip()
        ]

    # Extract tables
    # sqlmap heads the list with "Database: <name>", or with "<current>" for a DBMS
    # without databases (SQLite)
    table_section = re.search(
        r"(?:Database: (\S+)|(<current>))\s+\[\d+ tables?\]\s+(.+?)(?=\n\n|\Z)", output, re.DOTALL
    )
    if table_section:
        db_name = table_section.group(1) or table_section.group(2)
        tables = [
            t.strip().strip("| ")
            for t in table_section.group(3).strip().split("\n")
            if t.strip() and not t.startswith("+")
        ]
        findings["tables"] = {"database": db_name, "tables": tables}

    return findings


async def run_sqlmap_scan(
    target: str,
    scan_type: str = "scan",
    params: str | None = None,
    data: str | None = None,
    cookie: str | None = None,
    level: int = 1,
    risk: int = 1,
    dbms: str | None = None,
    database: str | None = None,
    table: str | None = None,
    columns: list[str] | None = None,
    timeout: int | None = None,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Execute a sqlmap scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    output_dir = Path(settings.output_dir) / f"scan_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        started_at=datetime.now(),
    )
    _remember(scan_results, scan_id, result, active_scans)
    active_scans.add(scan_id)

    # Build sqlmap command
    cmd = [
        sys.executable, settings.sqlmap_path,
        "-u", target,
        "--batch",  # Non-interactive
        "--output-dir", str(output_dir),
        f"--level={level}",
        f"--risk={risk}",
    ]

    # Add scan type specific options
    if scan_type == "scan":
        pass  # Basic scan, no extra options
    elif scan_type == "enumerate":
        if database:
            cmd.extend(["-D", database])
            if table:
                cmd.extend(["-T", table, "--columns"])
            else:
                cmd.append("--tables")
        else:
            cmd.append("--dbs")
    elif scan_type == "dump":
        if database:
            cmd.extend(["-D", database])
        if table:
            cmd.extend(["-T", table])
        if columns:
            cmd.extend(["-C", ",".join(columns)])
        cmd.append("--dump")

    # Add optional parameters
    if params:
        cmd.extend(["-p", params])
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if dbms:
        cmd.extend(["--dbms", dbms])
    if extra_args:
        cmd.extend(extra_args)

    logger.info(f"Starting {scan_type} scan {scan_id} for target: {target}")
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
        output = stdout.decode()
        result.raw_output = output

        if process.returncode == 0 or "sqlmap identified" in output.lower():
            result.status = "completed"

            # Parse findings
            parsed = parse_sqlmap_output(output)

            if parsed["injectable_params"]:
                result.vulnerabilities = parsed["injectable_params"]

            result.data = {
                "dbms": parsed["dbms"],
                "databases": parsed["databases"],
                "tables": parsed["tables"],
                "columns": parsed["columns"],
            }

            logger.info(
                f"Scan {scan_id} completed: {len(result.vulnerabilities)} injectable params found"
            )
        else:
            # Check if it's just "not injectable"
            if "not injectable" in output.lower() or "all tested parameters do not appear" in output.lower():
                result.status = "completed"
                result.data = {"message": "No SQL injection vulnerabilities found"}
            else:
                result.status = "failed"
                result.error = stderr.decode() if stderr else output[-500:]
                logger.error(f"Scan {scan_id} failed: {result.error}")

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


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "scan_type": result.scan_type,
        "status": result.status,
        "vulnerabilities": result.vulnerabilities,
        "data": result.data,
        "error": result.error,
    }


# Create MCP server
app = Server("sqlmap-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="sql_scan",
            description="Scan a URL for SQL injection vulnerabilities. "
            "Automatically tests all parameters for injection points.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL with parameters (e.g., http://example.com/page?id=1)",
                    },
                    "params": {
                        "type": "string",
                        "description": "Specific parameter(s) to test (comma-separated)",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST data string (e.g., 'user=admin&pass=test')",
                    },
                    "cookie": {
                        "type": "string",
                        "description": "HTTP Cookie header value",
                    },
                    "level": {
                        "type": "integer",
                        "description": "Level of tests (1-5, higher = more tests)",
                        "default": 1,
                        "minimum": 1,
                        "maximum": 5,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "Risk of tests (1-3, higher = more aggressive)",
                        "default": 1,
                        "minimum": 1,
                        "maximum": 3,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="sql_enumerate",
            description="Enumerate databases, tables, or columns from a vulnerable target. "
            "Requires a confirmed injectable parameter.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL with injectable parameter",
                    },
                    "database": {
                        "type": "string",
                        "description": "Database name (omit to list databases)",
                    },
                    "table": {
                        "type": "string",
                        "description": "Table name (omit to list tables)",
                    },
                    "dbms": {
                        "type": "string",
                        "description": "Force DBMS type (mysql, postgresql, mssql, oracle, sqlite)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="sql_dump",
            description="Dump data from database tables. Use responsibly and only on authorized targets.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL with injectable parameter",
                    },
                    "database": {
                        "type": "string",
                        "description": "Database name",
                    },
                    "table": {
                        "type": "string",
                        "description": "Table name",
                    },
                    "columns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific columns to dump",
                    },
                    "dbms": {
                        "type": "string",
                        "description": "Force DBMS type",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target", "database", "table"],
            },
        ),
        Tool(
            name="sql_test",
            description="Quick test to check if a parameter is injectable.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL with parameter to test",
                    },
                    "param": {
                        "type": "string",
                        "description": "Parameter name to test",
                    },
                },
                "required": ["target", "param"],
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
                        "description": "Include raw sqlmap output",
                        "default": False,
                    },
                },
                "required": ["scan_id"],
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
        if name == "sql_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_sqlmap_scan(
                target=_url(arguments.get("target")),
                scan_type="scan",
                params=_param_names(arguments.get("params")),
                data=_line(arguments.get("data"), "data"),
                cookie=_line(arguments.get("cookie"), "cookie"),
                level=_int(arguments.get("level"), "level", 1, 5, settings.default_level),
                risk=_int(arguments.get("risk"), "risk", 1, 3, settings.default_risk),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "sql_enumerate":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_sqlmap_scan(
                target=_url(arguments.get("target")),
                scan_type="enumerate",
                database=_name(arguments.get("database"), "database"),
                table=_name(arguments.get("table"), "table"),
                dbms=_name(arguments.get("dbms"), "dbms"),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "sql_dump":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_sqlmap_scan(
                target=_url(arguments.get("target")),
                scan_type="dump",
                database=_name(arguments.get("database"), "database"),
                table=_name(arguments.get("table"), "table"),
                columns=_columns(arguments.get("columns")),
                dbms=_name(arguments.get("dbms"), "dbms"),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "sql_test":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_sqlmap_scan(
                target=_url(arguments.get("target")),
                scan_type="scan",
                params=_param_names(arguments.get("param")),
                level=1,
                risk=1,
                timeout=120,
            )

            # Simplified response for quick test
            is_vulnerable = len(result.vulnerabilities) > 0
            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "scan_id": result.scan_id,
                        "target": result.target,
                        "parameter": arguments.get("param"),
                        "injectable": is_vulnerable,
                        "details": result.vulnerabilities if is_vulnerable else None,
                        "dbms": result.data.get("dbms"),
                    }, indent=2),
                )
            ]

        elif name == "get_scan_results":
            scan_id = str(arguments.get("scan_id", ""))
            result = scan_results.get(scan_id)

            if result:
                output = format_scan_summary(result)
                if arguments.get("include_raw") and result.raw_output:
                    output["raw_output"] = result.raw_output
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

        elif name == "list_active_scans":
            active = [
                {
                    "scan_id": scan_id,
                    "target": scan_results[scan_id].target,
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
            resources.append(
                Resource(
                    uri=f"sqlmap://results/{scan_id}",
                    name=f"Scan Results: {result.target}",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("sqlmap://results/"):
        scan_id = uri.replace("sqlmap://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting SQLMap MCP Server")
    logger.info(f"SQLMap path: {settings.sqlmap_path}")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure output directory exists
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
