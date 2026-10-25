# YARA - provenance and audit

| | |
|---|---|
| MCP server | FuzzingLabs mcp-security-hub, `binary-analysis/yara-mcp/server.py` |
| Upstream | https://github.com/FuzzingLabs/mcp-security-hub (removed from GitHub); authentic copy https://github.com/D4T4HUN73R/mcp-security-hub |
| Commit | `0409a5435666f6381d9057807e949cf02d98e8db` (2026-01-27) |
| Wrapper licence | MIT, Copyright (c) 2025 Fuzzing Labs (`LICENSES/FuzzingLabs-mcp-security-hub-MIT.txt`) |
| Tool | YARA 4.5.2, Debian trixie package `yara=4.5.2-1` |
| Tool licence | BSD-3-Clause (`LICENSES/debian-yara-copyright.txt`) |
| Rules | https://github.com/Yara-Rules/rules at `0f93570194a80d2f2032869055808b0ddcdfb360` (last commit 2022-04-12): the folders `crypto`, `packers`, `antidebug_antivm`, `capabilities`; only files that compile with YARA 4.5.2 and with each other go into `index.yar` (at build time all 9 files did) |
| Rules licence | GPL-2.0 (`LICENSES/Yara-Rules-GPL-2.0.txt`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools:** `yara_scan`, `yara_scan_with_rules`, `list_rulesets`, `get_scan_results`,
`list_active_scans`.

**Command execution:** `yara` is started with `asyncio.create_subprocess_exec` and an
argument list - no shell. Upstream passed the arguments unchecked:

- `target` was the last argument: a value starting with `-` became a YARA option (`-x
  module=file` feeds files to modules, `-d` defines variables, ...), and a bare number is a
  *process ID* to scan for the YARA command line;
- `rules_file` could be any absolute path in the container;
- inline `rules` were written to a file and compiled: YARA's `include "path"` directive reads
  other files, and compile errors (returned to the caller) can show parts of them.

**Network:** none. **Files:** reads targets from `/work`, rule files from the bundled rules,
`/rules` (an optional mount) or `/work`; writes inline rules to a temporary file in
`/tmp/yara-mcp` and deletes it after the scan.

**Rules:** the Yara-Rules project is no longer maintained (last commit 2022); only its
generic, format-independent folders are bundled, and every file is compile-checked at build
time, because one broken rule makes YARA refuse the whole index.

## Local patches

- `target` must resolve (symbolic links followed) under `/work` and is passed as an
  absolute path; `rules_file` must lie in the bundled rules, `/rules` or `/work`;
- inline rules: at most 1 MB, and any `include "` is refused (also inside comments - a false
  refusal is safe);
- directory scans add `-N` (do not follow symbolic links, which could lead out of `/work`)
  and `--skip-larger` with the configured maximum file size;
- `timeout` 1-3600 s; rules and output paths for the read-only image; results kept in memory
  are bounded (100); refused arguments return `Error: <why>`.

### The patch (unified diff against the upstream file, +103 / -32 lines)

```diff
--- a/binary-analysis/yara-mcp/server.py (FuzzingLabs 0409a54)
+++ b/servers/yara/src/server.py
@@ -11,12 +11,19 @@
     - list_rulesets: List available YARA rule sets
     - get_scan_results: Retrieve previous scan results
     - list_active_scans: Show running scans
+
+axross-mcp-hub patch: targets are read only from /work (the folder axross
+mounts) and passed as absolute paths; a rules_file must lie in the bundled rules,
+in /rules (an optional mount) or under /work; inline rules may not use
+"include" (it would read other files); directory scans do not follow symlinks;
+numbers are range-checked and stored results are bounded.
 """
 
 import asyncio
 import json
 import logging
 import os
+import re
 import uuid
 from datetime import datetime
 from pathlib import Path
@@ -43,8 +50,8 @@
 class Settings(BaseSettings):
     """Server configuration from environment variables."""
 
-    rules_dir: str = Field(default="/app/rules", alias="YARA_RULES_DIR")
-    output_dir: str = Field(default="/app/output", alias="YARA_OUTPUT_DIR")
+    rules_dir: str = Field(default="/opt/yara/rules", alias="YARA_RULES_DIR")
+    output_dir: str = Field(default="/tmp/yara-mcp", alias="YARA_OUTPUT_DIR")
     default_timeout: int = Field(default=300, alias="YARA_TIMEOUT")
     max_concurrent_scans: int = Field(default=2, alias="YARA_MAX_CONCURRENT")
     max_file_size: int = Field(default=104857600, alias="YARA_MAX_FILE_SIZE")  # 100MB
@@ -88,6 +95,83 @@
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
+# Any "include" directive is refused (also inside comments: a false refusal is safe).
+_INCLUDE = re.compile(r"\binclude\s*\"")
+
+
+def _rules_file(value) -> str:
+    """A rules file inside the bundled rules, /rules or the input folders."""
+    if not isinstance(value, str) or not value.strip() or "\x00" in value:
+        raise ArgumentError("rules_file: a .yar/.yara file (relative to the bundled rules)")
+    base = os.path.realpath(settings.rules_dir)
+    path = os.path.realpath(value if os.path.isabs(value) else os.path.join(base, value))
+    roots = [base, "/rules", *[os.path.realpath(r) for r in INPUT_ROOTS]]
+    if not any(path.startswith(r.rstrip("/") + "/") for r in roots) or not os.path.isfile(path):
+        raise ArgumentError("rules_file: a file in the bundled rules, in /rules or under "
+                            + ", ".join(INPUT_ROOTS))
+    return path
+
+
+def _inline_rules(value) -> str:
+    if not isinstance(value, str) or not value.strip():
+        raise ArgumentError("rules: YARA rule text")
+    if len(value) > 1_000_000:
+        raise ArgumentError("rules: at most 1 MB of rule text")
+    if _INCLUDE.search(value):
+        raise ArgumentError("rules: include is not allowed in inline rules")
+    return value
+
+
 def parse_yara_output(output: str) -> list[YaraMatch]:
     """Parse YARA command line output."""
     matches = []
@@ -159,7 +243,7 @@
         scan_type="file" if Path(target).is_file() else "directory",
         started_at=datetime.now(),
     )
-    scan_results[scan_id] = result
+    _remember(scan_results, scan_id, result, active_scans)
     active_scans.add(scan_id)
 
     # Determine rules to use
@@ -169,11 +253,8 @@
         rules_path.write_text(rules)
         rules_arg = str(rules_path)
     elif rules_file:
-        # Specific rules file
-        if not Path(rules_file).is_absolute():
-            rules_arg = str(Path(settings.rules_dir) / rules_file)
-        else:
-            rules_arg = rules_file
+        # Specific rules file (checked by _rules_file)
+        rules_arg = rules_file
     else:
         # Use all rules in rules directory
         rules_arg = str(Path(settings.rules_dir) / "index.yar")
@@ -185,7 +266,8 @@
     cmd = ["yara"]
 
     if recursive and Path(target).is_dir():
-        cmd.append("-r")
+        cmd.extend(["-r", "-N"])  # -N: symlinks could lead out of /work
+    cmd.append(f"--skip-larger={settings.max_file_size}")
 
     # Add warnings for better output
     cmd.append("-w")
@@ -260,7 +342,6 @@
 
     finally:
         active_scans.discard(scan_id)
-        scan_results[scan_id] = result
 
         # Clean up temp rules file
         if rules:
@@ -408,17 +489,14 @@
                     )
                 ]
 
-            target = arguments["target"]
-            if not Path(target).exists():
-                return [
-                    TextContent(type="text", text=f"Target not found: {target}")
-                ]
+            target = _input_path(arguments.get("target"), "target", kind="any")
+            rules_file = arguments.get("rules_file")
 
             result = await run_yara_scan(
                 target=target,
-                rules_file=arguments.get("rules_file"),
-                recursive=arguments.get("recursive", True),
-                timeout=arguments.get("timeout"),
+                rules_file=_rules_file(rules_file) if rules_file else None,
+                recursive=arguments.get("recursive", True) is not False,
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -437,23 +515,14 @@
                     )
                 ]
 
-            target = arguments["target"]
-            if not Path(target).exists():
-                return [
-                    TextContent(type="text", text=f"Target not found: {target}")
-                ]
-
-            rules = arguments["rules"]
-            if not rules.strip():
-                return [
-                    TextContent(type="text", text="Rules cannot be empty")
-                ]
+            target = _input_path(arguments.get("target"), "target", kind="any")
+            rules = _inline_rules(arguments.get("rules"))
 
             result = await run_yara_scan(
                 target=target,
                 rules=rules,
-                recursive=arguments.get("recursive", True),
-                timeout=arguments.get("timeout"),
+                recursive=arguments.get("recursive", True) is not False,
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -478,7 +547,7 @@
             ]
 
         elif name == "get_scan_results":
-            scan_id = arguments["scan_id"]
+            scan_id = str(arguments.get("scan_id", ""))
             result = scan_results.get(scan_id)
 
             if result:
@@ -525,6 +594,8 @@
         else:
             return [TextContent(type="text", text=f"Unknown tool: {name}")]
 
+    except ArgumentError as e:
+        return [TextContent(type="text", text=f"Error: {e}")]
     except Exception as e:
         logger.exception(f"Error executing tool {name}: {e}")
         return [TextContent(type="text", text=f"Error: {str(e)}")]
```
