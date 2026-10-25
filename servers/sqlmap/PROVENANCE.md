# sqlmap - provenance and audit

| | |
|---|---|
| MCP server | FuzzingLabs mcp-security-hub, `web-security/sqlmap-mcp/server.py` |
| Upstream | https://github.com/FuzzingLabs/mcp-security-hub (removed from GitHub); authentic copy https://github.com/D4T4HUN73R/mcp-security-hub |
| Commit | `0409a5435666f6381d9057807e949cf02d98e8db` (2026-01-27) |
| Wrapper licence | MIT, Copyright (c) 2025 Fuzzing Labs (`LICENSES/FuzzingLabs-mcp-security-hub-MIT.txt`) |
| Tool | sqlmap 1.10.10, https://github.com/sqlmapproject/sqlmap at `65b6e7b4acb13a736614a1ab73b0908476f3c24a` (tag 1.10.10) |
| Tool licence | GPL-2.0-or-later with sqlmap's clarifications (`LICENSES/sqlmap-LICENSE.txt`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools:** `sql_scan`, `sql_enumerate`, `sql_dump`, `sql_test`, `get_scan_results`,
`list_active_scans`.

**Command execution:** `python sqlmap.py ...` is started with `asyncio.create_subprocess_exec`
and an argument list - no shell; every value follows its option (`-u`, `-p`, `--data`, ...),
and `--batch` keeps sqlmap non-interactive. Upstream checked none of the values: `level` and
`risk` were formatted into `--level={level}` / `--risk={risk}` without a type check, and
`target`, `params`, `data`, `cookie`, `dbms`, `database`, `table` and `columns` were passed as
given. The server never passes sqlmap's file-system or OS-takeover options (`--file-read`,
`--os-shell`, ...).

**Network:** the targets, so axross's network must be Full.

**Files:** sqlmap's session and output go to `/tmp/sqlmap-mcp`; no user files are read.

**Bugs fixed:**

- The table parser expected `Database: <name>` above a table list; for a DBMS without
  databases (SQLite) sqlmap prints `<current>` there (checked with sqlmap 1.10.10), so
  `sql_enumerate` returned no tables. Both headings are parsed now.
- sqlmap was started as `python` from `PATH`; it now runs with the server's own interpreter.

**Licence note:** sqlmap's licence counts a program that "executes sqlmap and parses the
results" as a derived work under the GPL. This wrapper is MIT (GPL-compatible) and fully
published here; the image as a whole is distributed under the GPL's terms for sqlmap, with
all sources available (sqlmap at the commit above, the wrapper in this repository).

## Local patches

- `target`: an http(s) URL without whitespace; `params`: parameter names; `database`,
  `table`, `columns`, `dbms`: names; `data`, `cookie`: one line, at most 8192 characters;
  `level` 1-5, `risk` 1-3, `timeout` 1-3600 s; refused arguments return `Error: <why>`;
- sqlmap runs with `sys.executable`; output under `/tmp/sqlmap-mcp`;
- the SQLite table parser fix; results kept in memory are bounded (100).

### The patch (unified diff against the upstream file, +130 / -28 lines)

```diff
--- a/web-security/sqlmap-mcp/server.py (FuzzingLabs 0409a54)
+++ b/servers/sqlmap/src/server.py
@@ -11,6 +11,11 @@
     - sql_dump: Dump data from database
     - sql_test: Test specific parameters for injection
     - get_scan_results: Retrieve previous scan results
+
+axross-mcp-hub patch: every argument is validated before it reaches sqlmap's
+command line (an http(s) URL, names of parameters, databases, tables and
+columns, single-line data and cookie values, level 1-5, risk 1-3); sqlmap runs
+with this server's own Python interpreter; stored results are bounded.
 """
 
 import asyncio
@@ -18,6 +23,7 @@
 import logging
 import os
 import re
+import sys
 import uuid
 from datetime import datetime
 from pathlib import Path
@@ -45,7 +51,7 @@
     """Server configuration from environment variables."""
 
     sqlmap_path: str = Field(default="/opt/sqlmap/sqlmap.py", alias="SQLMAP_PATH")
-    output_dir: str = Field(default="/app/output", alias="SQLMAP_OUTPUT_DIR")
+    output_dir: str = Field(default="/tmp/sqlmap-mcp", alias="SQLMAP_OUTPUT_DIR")
     default_timeout: int = Field(default=300, alias="SQLMAP_TIMEOUT")
     max_concurrent_scans: int = Field(default=2, alias="SQLMAP_MAX_CONCURRENT")
     default_level: int = Field(default=1, alias="SQLMAP_LEVEL")
@@ -78,6 +84,99 @@
 active_scans: set[str] = set()
 
 
+# --- axross-mcp-hub: argument checks --------------------------------------------------
+#: Input files are read only from these folders (axross mounts the user's folder at /work).
+INPUT_ROOTS = tuple(p for p in os.environ.get("MCP_INPUT_ROOTS", "/work").split(":") if p)
+#: Results kept in memory (the oldest are dropped).
+MAX_STORED_RESULTS = 100
+MAX_TIMEOUT = 3600
+
+
+class ArgumentError(ValueError):
+    """A tool argument that is not accepted; the text says why."""
+
+
+def _input_path(value, what: str = "filepath", *, kind: str = "file") -> str:
+    """*value* as an absolute, symlink-free path under INPUT_ROOTS (relative paths are
+    taken from the first root). The result starts with "/", so it can never become an
+    option of the tool it is passed to. *kind*: file, dir or any."""
+    roots = [os.path.realpath(r) for r in INPUT_ROOTS]
+    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 4096:
+        raise ArgumentError(f"{what}: a path under {', '.join(INPUT_ROOTS)}")
+    path = os.path.realpath(value if os.path.isabs(value) else os.path.join(roots[0], value))
+    if not any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots):
+        raise ArgumentError(f"{what}: only paths under {', '.join(INPUT_ROOTS)} are read "
+                            "(mount the folder there)")
+    if kind == "file" and not os.path.isfile(path):
+        raise ArgumentError(f"{what}: {value} is not a file")
+    if kind == "dir" and not os.path.isdir(path):
+        raise ArgumentError(f"{what}: {value} is not a folder")
+    if kind == "any" and not os.path.exists(path):
+        raise ArgumentError(f"{what}: {value} not found")
+    return path
+
+
+def _int(value, name: str, low: int, high: int, default):
+    if value is None:
+        return default
+    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
+        raise ArgumentError(f"{name}: an integer from {low} to {high}")
+    return value
+
+
+def _remember(store: dict, key: str, value, active: set) -> None:
+    store[key] = value
+    while len(store) > MAX_STORED_RESULTS:
+        oldest = next(iter(store))
+        if oldest in active:
+            break
+        del store[oldest]
+# --------------------------------------------------------------------------------------
+
+
+_URL = re.compile(r"^https?://[^\s]{1,2040}$")
+_NAME = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.\-]{0,127}$")
+_NAMES = re.compile(r"^[A-Za-z0-9_$\[\]][A-Za-z0-9_$.\-\[\],]{0,511}$")
+
+
+def _url(value) -> str:
+    if not isinstance(value, str) or not _URL.match(value):
+        raise ArgumentError("target: an http:// or https:// URL without spaces")
+    return value
+
+
+def _name(value, what: str) -> str | None:
+    if value is None or value == "":
+        return None
+    if not isinstance(value, str) or not _NAME.match(value):
+        raise ArgumentError(f"{what}: letters, digits, '_', '$', '.' and '-'")
+    return value
+
+
+def _param_names(value) -> str | None:
+    if value is None or value == "":
+        return None
+    if not isinstance(value, str) or not _NAMES.match(value):
+        raise ArgumentError("params: parameter names separated by ','")
+    return value
+
+
+def _line(value, what: str) -> str | None:
+    if value is None or value == "":
+        return None
+    if not isinstance(value, str) or len(value) > 8192 or any(c in value for c in "\r\n\x00"):
+        raise ArgumentError(f"{what}: one line of text (at most 8192 characters)")
+    return value
+
+
+def _columns(value) -> list[str] | None:
+    if value is None:
+        return None
+    if not isinstance(value, list) or len(value) > 256:
+        raise ArgumentError("columns: a list of column names")
+    return [_name(v, "columns") for v in value]
+
+
 def parse_sqlmap_output(output: str) -> dict[str, Any]:
     """Parse sqlmap output for key findings."""
     findings = {
@@ -118,14 +217,16 @@
         ]
 
     # Extract tables
+    # sqlmap heads the list with "Database: <name>", or with "<current>" for a DBMS
+    # without databases (SQLite)
     table_section = re.search(
-        r"Database: (\w+)\s+\[\d+ tables?\]\s+(.+?)(?=\n\n|\Z)", output, re.DOTALL
+        r"(?:Database: (\S+)|(<current>))\s+\[\d+ tables?\]\s+(.+?)(?=\n\n|\Z)", output, re.DOTALL
     )
     if table_section:
-        db_name = table_section.group(1)
+        db_name = table_section.group(1) or table_section.group(2)
         tables = [
             t.strip().strip("| ")
-            for t in table_section.group(2).strip().split("\n")
+            for t in table_section.group(3).strip().split("\n")
             if t.strip() and not t.startswith("+")
         ]
         findings["tables"] = {"database": db_name, "tables": tables}
@@ -159,12 +260,12 @@
         scan_type=scan_type,
         started_at=datetime.now(),
     )
-    scan_results[scan_id] = result
+    _remember(scan_results, scan_id, result, active_scans)
     active_scans.add(scan_id)
 
     # Build sqlmap command
     cmd = [
-        "python", settings.sqlmap_path,
+        sys.executable, settings.sqlmap_path,
         "-u", target,
         "--batch",  # Non-interactive
         "--output-dir", str(output_dir),
@@ -267,7 +368,6 @@
 
     finally:
         active_scans.discard(scan_id)
-        scan_results[scan_id] = result
 
     return result
 
@@ -469,14 +569,14 @@
                 ]
 
             result = await run_sqlmap_scan(
-                target=arguments["target"],
+                target=_url(arguments.get("target")),
                 scan_type="scan",
-                params=arguments.get("params"),
-                data=arguments.get("data"),
-                cookie=arguments.get("cookie"),
-                level=arguments.get("level", settings.default_level),
-                risk=arguments.get("risk", settings.default_risk),
-                timeout=arguments.get("timeout"),
+                params=_param_names(arguments.get("params")),
+                data=_line(arguments.get("data"), "data"),
+                cookie=_line(arguments.get("cookie"), "cookie"),
+                level=_int(arguments.get("level"), "level", 1, 5, settings.default_level),
+                risk=_int(arguments.get("risk"), "risk", 1, 3, settings.default_risk),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -496,12 +596,12 @@
                 ]
 
             result = await run_sqlmap_scan(
-                target=arguments["target"],
+                target=_url(arguments.get("target")),
                 scan_type="enumerate",
-                database=arguments.get("database"),
-                table=arguments.get("table"),
-                dbms=arguments.get("dbms"),
-                timeout=arguments.get("timeout"),
+                database=_name(arguments.get("database"), "database"),
+                table=_name(arguments.get("table"), "table"),
+                dbms=_name(arguments.get("dbms"), "dbms"),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -521,13 +621,13 @@
                 ]
 
             result = await run_sqlmap_scan(
-                target=arguments["target"],
+                target=_url(arguments.get("target")),
                 scan_type="dump",
-                database=arguments["database"],
-                table=arguments["table"],
-                columns=arguments.get("columns"),
-                dbms=arguments.get("dbms"),
-                timeout=arguments.get("timeout"),
+                database=_name(arguments.get("database"), "database"),
+                table=_name(arguments.get("table"), "table"),
+                columns=_columns(arguments.get("columns")),
+                dbms=_name(arguments.get("dbms"), "dbms"),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -547,9 +647,9 @@
                 ]
 
             result = await run_sqlmap_scan(
-                target=arguments["target"],
+                target=_url(arguments.get("target")),
                 scan_type="scan",
-                params=arguments.get("param"),
+                params=_param_names(arguments.get("param")),
                 level=1,
                 risk=1,
                 timeout=120,
@@ -572,7 +672,7 @@
             ]
 
         elif name == "get_scan_results":
-            scan_id = arguments["scan_id"]
+            scan_id = str(arguments.get("scan_id", ""))
             result = scan_results.get(scan_id)
 
             if result:
@@ -619,6 +719,8 @@
         else:
             return [TextContent(type="text", text=f"Unknown tool: {name}")]
 
+    except ArgumentError as e:
+        return [TextContent(type="text", text=f"Error: {e}")]
     except Exception as e:
         logger.exception(f"Error executing tool {name}: {e}")
         return [TextContent(type="text", text=f"Error: {str(e)}")]
```
