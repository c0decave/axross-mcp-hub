# capa - provenance and audit

| | |
|---|---|
| MCP server | FuzzingLabs mcp-security-hub, `binary-analysis/capa-mcp/server.py` |
| Upstream | https://github.com/FuzzingLabs/mcp-security-hub (removed from GitHub); authentic copy https://github.com/D4T4HUN73R/mcp-security-hub |
| Commit | `0409a5435666f6381d9057807e949cf02d98e8db` (2026-01-27) |
| Wrapper licence | MIT, Copyright (c) 2025 Fuzzing Labs (`LICENSES/FuzzingLabs-mcp-security-hub-MIT.txt`) |
| Tool | Mandiant capa 10.0.0 (`flare-capa==10.0.0` from PyPI, hash-locked in `requirements.txt`) |
| Rules | https://github.com/mandiant/capa-rules at `805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5` (tag v10.0.0) |
| FLIRT signatures | `sigs/` of https://github.com/mandiant/capa at `85813ebc5b99ccdbe43147e46796d0bd6700f30a` (tag v10.0.0) |
| Tool licence | Apache-2.0 (`LICENSES/capa-Apache-2.0.txt`, `LICENSES/capa-rules-Apache-2.0.txt`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools:** `capa_analyze`, `get_analysis_results`, `list_active_scans`.

**Command execution:** `capa` is started with `asyncio.create_subprocess_exec` and an
argument list - no shell. Upstream passed `filepath` unchecked (a value starting with `-`
became a capa option such as `-r <dir>` or `-s <dir>`), and any path in the container was
readable.

**Network:** none. **Files:** reads samples from `/work`; writes capa's JSON report to
`/tmp/capa-mcp`.

**Behaviour fixed:**

- Upstream installed capa's standalone release binary and passed `-r /app/rules`, an empty
  folder created by the image - which *replaces* capa's embedded rules, so capa matched
  nothing. The image now carries the pinned capa-rules release and capa's FLIRT signatures,
  and capa is always called with `-r /opt/capa/rules -s /opt/capa/sigs`.
- The standalone binary is a PyInstaller one-file program that unpacks itself to `/tmp` and
  runs from there; axross mounts `/tmp` `noexec`. capa is therefore installed from PyPI
  (hash-locked, wheels only) into a virtual environment.

**Dependencies:** `flare-capa` pulls `ida-hcli` (IDA Pro's helper, unused here), which
depends on `pip`. pip vendors its own copies of urllib3, msgpack and setuptools, which Trivy
reported with HIGH vulnerabilities. Like every Python image of this hub, the image removes
pip from the virtual environment after the install (capa does not need it at run time;
checked with the live test), and the scan is clean of HIGH and CRITICAL findings with fixes.

## Local patches

- `filepath` must resolve (symbolic links followed) to a file under `/work` and is passed as
  an absolute path; `timeout` 1-3600 s;
- rules and signatures from the image (above); output under `/tmp/capa-mcp`;
- results kept in memory are bounded (100); the docstring no longer lists a `capa_rules`
  tool that never existed.

### The patch (unified diff against the upstream file, +65 / -16 lines)

```diff
--- a/binary-analysis/capa-mcp/server.py (FuzzingLabs 0409a54)
+++ b/servers/capa/src/server.py
@@ -7,14 +7,19 @@
 
 Tools:
     - capa_analyze: Analyze binary capabilities
-    - capa_rules: List matching rules for a binary
     - get_analysis_results: Retrieve previous analysis
     - list_active_scans: Show running analyses
+
+axross-mcp-hub patch: files are read only from /work (the folder axross mounts)
+and passed as absolute paths; capa runs with the pinned capa-rules and FLIRT
+signatures baked into the image (an empty rules folder used to replace capa's
+rules); numbers are range-checked and stored results are bounded.
 """
 
 import asyncio
 import json
 import logging
+import os
 import uuid
 from datetime import datetime
 from pathlib import Path
@@ -34,8 +39,9 @@
 
 
 class Settings(BaseSettings):
-    output_dir: str = Field(default="/app/output", alias="CAPA_OUTPUT_DIR")
-    rules_dir: str = Field(default="/app/rules", alias="CAPA_RULES_DIR")
+    output_dir: str = Field(default="/tmp/capa-mcp", alias="CAPA_OUTPUT_DIR")
+    rules_dir: str = Field(default="/opt/capa/rules", alias="CAPA_RULES_DIR")
+    sigs_dir: str = Field(default="/opt/capa/sigs", alias="CAPA_SIGS_DIR")
     default_timeout: int = Field(default=300, alias="CAPA_TIMEOUT")
     max_concurrent_scans: int = Field(default=2, alias="CAPA_MAX_CONCURRENT")
 
@@ -70,6 +76,56 @@
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
 def parse_capa_json(output: str) -> list[Capability]:
     capabilities = []
     try:
@@ -113,14 +169,11 @@
         filepath=filepath,
         started_at=datetime.now(),
     )
-    scan_results[scan_id] = result
+    _remember(scan_results, scan_id, result, active_scans)
     active_scans.add(scan_id)
 
-    cmd = ["capa", "-j", filepath]
-
-    # Add rules directory if exists
-    if Path(settings.rules_dir).exists():
-        cmd.extend(["-r", settings.rules_dir])
+    # The rules and signatures are part of the image; the path is absolute.
+    cmd = ["capa", "-j", "-r", settings.rules_dir, "-s", settings.sigs_dir, filepath]
 
     logger.info(f"Starting capa analysis {scan_id} for: {filepath}")
 
@@ -177,7 +230,6 @@
 
     finally:
         active_scans.discard(scan_id)
-        scan_results[scan_id] = result
 
     return result
 
@@ -254,18 +306,16 @@
             if len(active_scans) >= settings.max_concurrent_scans:
                 return [TextContent(type="text", text="Max concurrent scans reached.")]
 
-            filepath = arguments["filepath"]
-            if not Path(filepath).exists():
-                return [TextContent(type="text", text=f"File not found: {filepath}")]
+            filepath = _input_path(arguments.get("filepath"))
 
             result = await run_capa_analysis(
                 filepath=filepath,
-                timeout=arguments.get("timeout"),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
             return [TextContent(type="text", text=json.dumps(format_analysis_summary(result), indent=2))]
 
         elif name == "get_analysis_results":
-            result = scan_results.get(arguments["scan_id"])
+            result = scan_results.get(str(arguments.get("scan_id", "")))
             if result:
                 return [TextContent(type="text", text=json.dumps(format_analysis_summary(result), indent=2))]
             return [TextContent(type="text", text="Analysis not found")]
@@ -306,7 +356,6 @@
 async def main():
     logger.info("Starting Capa MCP Server")
     Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
-    Path(settings.rules_dir).mkdir(parents=True, exist_ok=True)
 
     async with stdio_server() as (read_stream, write_stream):
         await app.run(read_stream, write_stream, app.create_initialization_options())
```
