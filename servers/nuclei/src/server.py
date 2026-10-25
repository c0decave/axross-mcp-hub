#!/usr/bin/env python3
"""
Nuclei MCP Server

A Model Context Protocol server that provides vulnerability scanning
capabilities using ProjectDiscovery's Nuclei scanner.

Tools:
    - nuclei_scan: Comprehensive vulnerability scan with templates
    - quick_scan: Fast scan with common vulnerability templates
    - template_scan: Scan with specific template categories
    - list_templates: List available template categories
    - get_scan_results: Retrieve previous scan results
    - list_active_scans: Show running scans

axross-mcp-hub patch: targets, tags and severities are validated before they reach
nuclei's command line; the templates are the pinned set baked into the image
(no update check, no download at start); interactsh (out-of-band callbacks to a
third-party server) is off; template categories select template folders (they
were passed as tags before, which matched nothing); numbers are range-checked and
stored results are bounded.
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
logger = logging.getLogger("nuclei-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    templates_dir: str = Field(default="/opt/nuclei-templates", alias="NUCLEI_TEMPLATES_PATH")
    output_dir: str = Field(default="/tmp/nuclei-mcp", alias="NUCLEI_OUTPUT_DIR")
    default_timeout: int = Field(default=600, alias="NUCLEI_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="NUCLEI_MAX_CONCURRENT")
    rate_limit: int = Field(default=150, alias="NUCLEI_RATE_LIMIT")

    class Config:
        env_prefix = "NUCLEI_"


settings = Settings()


class Finding(BaseModel):
    """Model for a single vulnerability finding."""

    template_id: str
    template_name: str | None = None
    severity: str
    host: str
    matched_at: str | None = None
    extracted_results: list[str] = []
    matcher_name: str | None = None
    description: str | None = None
    tags: list[str] = []


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    findings: list[Finding] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()

# Template categories: the template folders they select (headless needs a browser
# and file templates scan local files, so neither is offered)
CATEGORY_PATHS = {
    "cves": "http/cves",
    "vulnerabilities": "http/vulnerabilities",
    "exposures": "http/exposures",
    "misconfiguration": "http/misconfiguration",
    "technologies": "http/technologies",
    "default-logins": "http/default-logins",
    "takeovers": "http/takeovers",
    "fuzzing": "http/fuzzing",
    "iot": "http/iot",
    "network": "network",
    "ssl": "ssl",
    "dns": "dns",
}
TEMPLATE_CATEGORIES = list(CATEGORY_PATHS)

SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

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


# http(s)://host[:port][/path] or host[:port]; never starts with "-", no whitespace
_TARGET = re.compile(r"^(?:https?://)?[A-Za-z0-9\[][A-Za-z0-9.\-_:\[\]]{0,253}(?:/[^\s]{0,2000})?$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,63}$")


def _target(value) -> str:
    if not isinstance(value, str) or not _TARGET.match(value):
        raise ArgumentError("target: a URL (http:// or https://) or host[:port]")
    return value


def _names(value, what: str, allowed=None) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 64 or not all(
        isinstance(v, str) and _TAG.match(v) and (allowed is None or v in allowed) for v in value
    ):
        hint = f"one of {', '.join(allowed)}" if allowed else "letters, digits, '.', '_' and '-'"
        raise ArgumentError(f"{what}: a list of names ({hint})")
    return value


def parse_nuclei_jsonl(output: str) -> list[Finding]:
    """Parse nuclei JSONL output into findings."""
    findings = []

    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            finding = Finding(
                template_id=data.get("template-id", data.get("templateID", "unknown")),
                template_name=data.get("info", {}).get("name"),
                severity=data.get("info", {}).get("severity", "unknown"),
                host=data.get("host", data.get("matched-at", "")),
                matched_at=data.get("matched-at"),
                extracted_results=data.get("extracted-results", []),
                matcher_name=data.get("matcher-name"),
                description=data.get("info", {}).get("description"),
                tags=data.get("info", {}).get("tags", []),
            )
            findings.append(finding)
        except json.JSONDecodeError:
            # Skip non-JSON lines (progress output, etc.)
            continue
        except Exception as e:
            logger.warning(f"Error parsing finding: {e}")
            continue

    return findings


def parse_nuclei_text(output: str) -> list[Finding]:
    """Parse nuclei text output as fallback."""
    findings = []

    # Pattern: [template-id] [severity] matched-url
    pattern = r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.+)"

    for line in output.split("\n"):
        match = re.search(pattern, line)
        if match:
            finding = Finding(
                template_id=match.group(1),
                severity=match.group(2).lower(),
                host=match.group(4).strip(),
                matched_at=match.group(4).strip(),
            )
            findings.append(finding)

    return findings


async def run_nuclei_scan(
    target: str,
    scan_type: str = "scan",
    templates: list[str] | None = None,
    tags: list[str] | None = None,
    severity: list[str] | None = None,
    rate_limit: int | None = None,
    timeout: int | None = None,
    extra_args: list[str] | None = None,
) -> ScanResult:
    """Execute a nuclei scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"scan_{scan_id}.jsonl"

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        started_at=datetime.now(),
    )
    _remember(scan_results, scan_id, result, active_scans)
    active_scans.add(scan_id)

    # Build nuclei command
    cmd = [
        "nuclei",
        "-target", target,
        "-jsonl",
        "-output", str(output_file),
        "-rate-limit", str(rate_limit or settings.rate_limit),
        "-silent",
        "-disable-update-check",  # the templates are pinned in the image
        "-no-interactsh",         # no out-of-band callbacks to a third-party server
        "-no-color",
    ]

    # Add scan type specific options
    if scan_type == "template" and templates:
        # Specific categories: their template folders
        for category in templates:
            cmd.extend(["-templates", str(Path(settings.templates_dir) / CATEGORY_PATHS[category])])
    else:
        cmd.extend(["-templates", settings.templates_dir])
    if scan_type == "quick":
        # Quick scan: only high/critical, common templates
        cmd.extend(["-severity", "high,critical"])
        cmd.extend(["-tags", "cve,rce,lfi,xss,sqli,ssrf"])
    elif scan_type == "full":
        # Full scan with all templates
        pass  # No additional filters

    # Add severity filter
    if severity:
        cmd.extend(["-severity", ",".join(severity)])

    # Add tag filter
    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    # Add extra arguments
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

        # Read output file if exists
        if output_file.exists():
            output_content = output_file.read_text()
            result.raw_output = output_content
            result.findings = parse_nuclei_jsonl(output_content)
        else:
            # Try parsing stdout
            stdout_text = stdout.decode()
            result.raw_output = stdout_text
            result.findings = parse_nuclei_text(stdout_text)

        # Generate stats
        severity_counts = {}
        for finding in result.findings:
            sev = finding.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        result.stats = {
            "total_findings": len(result.findings),
            "by_severity": severity_counts,
            "unique_templates": len(set(f.template_id for f in result.findings)),
        }

        if process.returncode == 0 or len(result.findings) >= 0:
            result.status = "completed"
            logger.info(f"Scan {scan_id} completed: {len(result.findings)} findings")
        else:
            result.status = "failed"
            result.error = stderr.decode() if stderr else "Unknown error"
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
    findings_summary = []
    for finding in result.findings:
        findings_summary.append({
            "template_id": finding.template_id,
            "template_name": finding.template_name,
            "severity": finding.severity,
            "host": finding.host,
            "matched_at": finding.matched_at,
            "tags": finding.tags,
        })

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "scan_type": result.scan_type,
        "status": result.status,
        "stats": result.stats,
        "findings": findings_summary,
        "error": result.error,
    }


# Create MCP server
app = Server("nuclei-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="nuclei_scan",
            description="Comprehensive vulnerability scan using Nuclei templates. "
            "Scans for CVEs, misconfigurations, exposures, and more.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or host (e.g., https://example.com, 192.168.1.1)",
                    },
                    "severity": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": SEVERITY_LEVELS,
                        },
                        "description": "Filter by severity levels (info, low, medium, high, critical)",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by template tags (e.g., cve, rce, xss, sqli)",
                    },
                    "rate_limit": {
                        "type": "integer",
                        "description": "Maximum requests per second",
                        "default": 150,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="quick_scan",
            description="Fast vulnerability scan focusing on high/critical severity issues. "
            "Good for initial reconnaissance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or host",
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
            name="template_scan",
            description="Scan with specific template categories. "
            "Available categories: cves, vulnerabilities, exposures, misconfiguration, "
            "technologies, default-logins, takeovers, file, fuzzing, network, ssl, dns.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or host",
                    },
                    "templates": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": TEMPLATE_CATEGORIES,
                        },
                        "description": "Template categories to use",
                    },
                    "severity": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": SEVERITY_LEVELS,
                        },
                        "description": "Filter by severity levels",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 600,
                    },
                },
                "required": ["target", "templates"],
            },
        ),
        Tool(
            name="list_templates",
            description="List available Nuclei template categories and common tags.",
            inputSchema={
                "type": "object",
                "properties": {},
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
                        "description": "Include raw nuclei output",
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
        if name == "nuclei_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_nuclei_scan(
                target=_target(arguments.get("target")),
                scan_type="scan",
                severity=_names(arguments.get("severity"), "severity", SEVERITY_LEVELS),
                tags=_names(arguments.get("tags"), "tags"),
                rate_limit=_int(arguments.get("rate_limit"), "rate_limit", 1, 1000, None),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "quick_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_nuclei_scan(
                target=_target(arguments.get("target")),
                scan_type="quick",
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, 300),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "template_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            result = await run_nuclei_scan(
                target=_target(arguments.get("target")),
                scan_type="template",
                templates=_names(arguments.get("templates"), "templates", TEMPLATE_CATEGORIES),
                severity=_names(arguments.get("severity"), "severity", SEVERITY_LEVELS),
                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "list_templates":
            common_tags = [
                "cve", "rce", "lfi", "xss", "sqli", "ssrf", "redirect",
                "exposure", "config", "auth-bypass", "default-login",
                "takeover", "tech", "token", "creds", "panel",
            ]

            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "categories": TEMPLATE_CATEGORIES,
                        "common_tags": common_tags,
                        "severity_levels": SEVERITY_LEVELS,
                        "templates_path": settings.templates_dir,
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
            finding_count = len(result.findings)
            resources.append(
                Resource(
                    uri=f"nuclei://results/{scan_id}",
                    name=f"Scan Results: {result.target} ({finding_count} findings)",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("nuclei://results/"):
        scan_id = uri.replace("nuclei://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting Nuclei MCP Server")
    logger.info(f"Templates directory: {settings.templates_dir}")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure output directory exists
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
