#!/usr/bin/env python3
"""gitleaks MCP server (axross-mcp-hub): find secrets (keys, tokens, passwords) in files
and in git history.

Tools:
    - scan_directory: scan the files under a folder (gitleaks dir)
    - scan_git_history: scan every commit of a git repository (gitleaks git)
    - list_rules: the detection rules of the built-in configuration

Only paths under /work (the folder axross mounts) are scanned. Findings are redacted by
default: the answer names the rule, file, line, commit and a redacted match, not the secret.
A custom configuration may be given as a .toml file under /work. gitleaks runs with an
argument list (never a shell); the report goes to a private temporary file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import tempfile

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("gitleaks-mcp")

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

GITLEAKS = "gitleaks"
DEFAULT_TIMEOUT = 600
_RULE_ID = re.compile(r'^\s*id\s*=\s*"([^"]+)"', re.MULTILINE)
KEEP = ("RuleID", "Description", "File", "StartLine", "EndLine", "StartColumn", "Match",
        "Secret", "Entropy", "Commit", "Author", "Date", "Message", "Fingerprint", "Tags")

mcp = FastMCP("gitleaks-mcp")


def _config(value) -> list[str]:
    if value in (None, ""):
        return []
    path = _input_path(value, "config")
    if not path.endswith(".toml"):
        raise ArgumentError("config: a gitleaks .toml file")
    return ["--config", path]


#: git configuration forced on every git call gitleaks makes: a mounted repository
#: belongs to another user (safe.directory), and its own config must not make git run
#: programs (fsmonitor, hooks; textconv and external diffs are off through --log-opts).
GIT_CONFIG = (("safe.directory", "*"), ("core.fsmonitor", "false"),
              ("core.hooksPath", "/dev/null"), ("diff.external", ""))
#: git log options of a history scan: gitleaks' defaults plus no textconv / external diff
LOG_OPTS = "--full-history --all --no-textconv --no-ext-diff"


def _env() -> dict:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp",
           "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_COUNT": str(len(GIT_CONFIG))}
    for i, (key, value) in enumerate(GIT_CONFIG):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


def _scan(mode: str, target: str, redact: bool, config: list[str], max_mb: int,
          timeout: int) -> list[dict]:
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        report = os.path.join(tmp, "report.json")
        argv = [GITLEAKS, mode, "--no-banner", "--no-color", "--log-level", "error",
                "--exit-code", "0", "--report-format", "json", "--report-path", report,
                "--max-target-megabytes", str(max_mb), *config]
        if redact:
            argv.append("--redact")
        if mode == "git":
            argv.append(f"--log-opts={LOG_OPTS}")
        argv.append(target)
        code, out, err = _run(argv, timeout, env=_env())
        if code != 0:
            raise ArgumentError(f"gitleaks failed (exit {code}): {_clip((err or out).strip(), 2000)}")
        with open(report, encoding="utf-8") as handle:
            return json.load(handle) or []


def _answer(target: str, findings: list[dict], limit: int) -> dict:
    rows = [{k: f.get(k) for k in KEEP if f.get(k) not in (None, "", [])} for f in findings]
    by_rule: dict[str, int] = {}
    for row in rows:
        by_rule[row.get("RuleID", "?")] = by_rule.get(row.get("RuleID", "?"), 0) + 1
    return {"target": target, "findings": len(rows), "by_rule": by_rule,
            "returned": min(len(rows), limit), "results": rows[:limit]}


@mcp.tool()
async def scan_directory(path: str = "/work", redact: bool = True, config: str = "",
                         max_findings: int = 200, max_file_mb: int = 20,
                         timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Scan the files under *path* (a folder or file under /work) for secrets.
    redact: replace the secrets in the answer (default); config: a gitleaks .toml under
    /work (default: the built-in rules); max_findings 1-5000; max_file_mb 1-500."""
    try:
        target = _input_path(path, "path", kind="any")
        findings = await asyncio.to_thread(
            _scan, "dir", target, redact is not False, _config(config),
            _int(max_file_mb, "max_file_mb", 1, 500, 20),
            _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return _answer(target, findings, _int(max_findings, "max_findings", 1, 5000, 200))
    except (ArgumentError, OSError, ValueError) as exc:
        return {"error": str(exc)}


@mcp.tool()
async def scan_git_history(repository: str = "/work", redact: bool = True, config: str = "",
                           max_findings: int = 200, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Scan every commit of the git repository at *repository* (under /work) for secrets,
    including ones deleted later. Findings name the commit, author and date."""
    try:
        target = _input_path(repository, "repository", kind="dir")
        if not os.path.exists(os.path.join(target, ".git")):
            raise ArgumentError(f"repository: {repository} has no .git")
        findings = await asyncio.to_thread(
            _scan, "git", target, redact is not False, _config(config), 50,
            _int(timeout, "timeout", 1, MAX_TIMEOUT, DEFAULT_TIMEOUT))
        return _answer(target, findings, _int(max_findings, "max_findings", 1, 5000, 200))
    except (ArgumentError, OSError, ValueError) as exc:
        return {"error": str(exc)}


@mcp.tool()
async def list_rules() -> dict:
    """The IDs of the built-in detection rules (gitleaks' default configuration)."""
    path = "/opt/gitleaks/gitleaks.toml"
    try:
        with open(path, encoding="utf-8") as handle:
            ids = _RULE_ID.findall(handle.read())
    except OSError as exc:
        return {"error": str(exc)}
    return {"rules": len(ids), "ids": ids}


if __name__ == "__main__":
    mcp.run("stdio")
