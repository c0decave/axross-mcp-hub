# binwalk - provenance and audit

| | |
|---|---|
| MCP server | FuzzingLabs mcp-security-hub, `binary-analysis/binwalk-mcp/server.py` |
| Upstream | https://github.com/FuzzingLabs/mcp-security-hub (removed from GitHub); authentic copy https://github.com/D4T4HUN73R/mcp-security-hub |
| Commit | `0409a5435666f6381d9057807e949cf02d98e8db` (2026-01-27) |
| Wrapper licence | MIT, Copyright (c) 2025 Fuzzing Labs (`LICENSES/FuzzingLabs-mcp-security-hub-MIT.txt`) |
| Tool | binwalk 2.4.3 (OSPG fork), Debian trixie package `binwalk=2.4.3+dfsg1-2+deb13u1`, plus the extractors `7zip`, `squashfs-tools`, `cpio`, `unzip`, `lzop`, `xz-utils`, `bzip2` and `xxd` (versions pinned in the Dockerfile) |
| Tool licence | MIT/Expat (`LICENSES/debian-binwalk-copyright.txt`); the extractors' licences are in the image under `/usr/share/doc/<package>/copyright` |
| Python packages | `requirements.txt` (hash-locked) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools:** `binwalk_scan`, `binwalk_extract`, `binwalk_entropy`, `binwalk_hexdump`,
`get_scan_results`, `list_extractions`, `list_active_scans`.

**Command execution:** `binwalk` and `xxd` are started with `asyncio.create_subprocess_exec`
and an argument list - no shell. Upstream passed `filepath` unchecked as the last argument
and only tested `Path(filepath).exists()` relative to the working directory. A file whose
name starts with `-` would have become a binwalk option - including `-D/--dd
type:ext:cmd`, which *runs a command* for every extracted file. Any path in the container
was readable. `offset` and `length` of the hex dump were not type-checked.

**Network:** none.

**Files:** reads the firmware from `/work` (the folder axross mounts); extraction writes to
`/out` when a writable folder is mounted there, else to `/tmp/binwalk-mcp` (axross's tmpfs,
64 MiB). Extraction runs third-party extractors on untrusted data; in axross's container
they have no capabilities, no network, a read-only root and a `noexec` /tmp. binwalk 2.4.3
contains the fix for the PFS extractor path traversal (CVE-2022-4510, fixed in 2.3.4).

**Behaviour fixed:**

- binwalk 2.3+ refuses to extract as root unless `--run-as=root` is given. axross runs the
  container as its root (rootless podman maps it to the user, no capabilities) whenever a
  folder is mounted, so `binwalk_extract` always failed there; the flag is now added when the
  effective UID is 0.
- `binwalk -E` tries to open a plot window; `-N` (no plot) is added.

## Local patches

- `filepath` must resolve (symbolic links followed) to a file under `/work`; it is passed as
  an absolute path, so it can never start with `-`;
- `timeout` 1-3600 s, `offset` >= 0, `length` 1-4096 are checked;
- extraction goes to `/out` (if writable) or `/tmp/binwalk-mcp`; the unused upload folder
  is gone;
- `--run-as=root` when running as UID 0, `-N` for the entropy scan;
- results kept in memory are bounded (100); refused arguments return `Error: <why>`.

### The patch (unified diff against the upstream file, +85 / -35 lines)

```diff
--- a/binary-analysis/binwalk-mcp/server.py (FuzzingLabs 0409a54)
+++ b/servers/binwalk/src/server.py
@@ -11,7 +11,13 @@
     - binwalk_entropy: Analyze entropy to detect compression/encryption
     - binwalk_hexdump: Display hex dump of file sections
     - list_extractions: List completed extractions
-    - get_extraction_contents: Get contents of extracted files
+    - get_scan_results: Retrieve results from a previous scan
+
+axross-mcp-hub patch: files are read only from /work (the folder axross mounts),
+every path is resolved and passed as an absolute path (never an option), numbers
+are range-checked, extraction goes to /out when a writable folder is mounted
+there (else /tmp, 64 MiB), the entropy scan does not try to plot, and stored
+results are bounded.
 """
 
 import asyncio
@@ -44,8 +50,7 @@
 class Settings(BaseSettings):
     """Server configuration from environment variables."""
 
-    output_dir: str = Field(default="/app/output", alias="BINWALK_OUTPUT_DIR")
-    upload_dir: str = Field(default="/app/uploads", alias="BINWALK_UPLOAD_DIR")
+    output_dir: str = Field(default="/tmp/binwalk-mcp", alias="BINWALK_OUTPUT_DIR")
     default_timeout: int = Field(default=300, alias="BINWALK_TIMEOUT")
     max_concurrent_scans: int = Field(default=2, alias="BINWALK_MAX_CONCURRENT")
     max_file_size: int = Field(default=104857600, alias="BINWALK_MAX_FILE_SIZE")  # 100MB
@@ -97,6 +102,64 @@
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
+def _extraction_base() -> Path:
+    """/out when the user mounted a writable folder there, else the output dir."""
+    out = Path("/out")
+    if out.is_dir() and os.access(out, os.W_OK):
+        return out
+    return Path(settings.output_dir)
+
+
 def parse_binwalk_output(output: str) -> list[SignatureMatch]:
     """Parse binwalk signature scan output."""
     signatures = []
@@ -172,19 +235,23 @@
         scan_type=scan_type,
         started_at=datetime.now(),
     )
-    scan_results[scan_id] = result
+    _remember(scan_results, scan_id, result, active_scans)
     active_scans.add(scan_id)
 
     # Build binwalk command based on scan type
-    extraction_dir = Path(settings.output_dir) / f"extract_{scan_id}"
+    extraction_dir = _extraction_base() / f"extract_{scan_id}"
 
     if scan_type == "signature":
         cmd = ["binwalk", filepath]
     elif scan_type == "extract":
         cmd = ["binwalk", "-e", "-C", str(extraction_dir), filepath]
+        if os.geteuid() == 0:
+            # axross runs the container as its (rootless, capability-free) root when a
+            # folder is mounted; binwalk refuses to extract as root without this.
+            cmd[1:1] = ["--run-as=root"]
         result.extraction_path = str(extraction_dir)
     elif scan_type == "entropy":
-        cmd = ["binwalk", "-E", filepath]
+        cmd = ["binwalk", "-E", "-N", filepath]  # -N: no plot window
     elif scan_type == "hexdump":
         cmd = ["binwalk", "-W", filepath]
     else:
@@ -260,7 +327,6 @@
 
     finally:
         active_scans.discard(scan_id)
-        scan_results[scan_id] = result
 
     return result
 
@@ -458,16 +524,12 @@
                     )
                 ]
 
-            filepath = arguments["filepath"]
-            if not Path(filepath).exists():
-                return [
-                    TextContent(type="text", text=f"File not found: {filepath}")
-                ]
+            filepath = _input_path(arguments.get("filepath"))
 
             result = await run_binwalk_scan(
                 filepath=filepath,
                 scan_type="signature",
-                timeout=arguments.get("timeout"),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -486,17 +548,13 @@
                     )
                 ]
 
-            filepath = arguments["filepath"]
-            if not Path(filepath).exists():
-                return [
-                    TextContent(type="text", text=f"File not found: {filepath}")
-                ]
+            filepath = _input_path(arguments.get("filepath"))
 
             result = await run_binwalk_scan(
                 filepath=filepath,
                 scan_type="extract",
                 extract=True,
-                timeout=arguments.get("timeout", 600),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, 600),
             )
 
             return [
@@ -507,16 +565,12 @@
             ]
 
         elif name == "binwalk_entropy":
-            filepath = arguments["filepath"]
-            if not Path(filepath).exists():
-                return [
-                    TextContent(type="text", text=f"File not found: {filepath}")
-                ]
+            filepath = _input_path(arguments.get("filepath"))
 
             result = await run_binwalk_scan(
                 filepath=filepath,
                 scan_type="entropy",
-                timeout=arguments.get("timeout", 120),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, 120),
             )
 
             output = format_scan_summary(result)
@@ -531,14 +585,10 @@
             ]
 
         elif name == "binwalk_hexdump":
-            filepath = arguments["filepath"]
-            if not Path(filepath).exists():
-                return [
-                    TextContent(type="text", text=f"File not found: {filepath}")
-                ]
+            filepath = _input_path(arguments.get("filepath"))
 
-            offset = arguments.get("offset", 0)
-            length = min(arguments.get("length", 256), 4096)  # Max 4KB
+            offset = _int(arguments.get("offset"), "offset", 0, 2**62, 0)
+            length = _int(arguments.get("length"), "length", 1, 4096, 256)  # Max 4KB
 
             hexdump = await get_hexdump(filepath, offset, length)
 
@@ -555,7 +605,7 @@
             ]
 
         elif name == "get_scan_results":
-            scan_id = arguments["scan_id"]
+            scan_id = str(arguments.get("scan_id", ""))
             result = scan_results.get(scan_id)
 
             if result:
@@ -624,6 +674,8 @@
         else:
             return [TextContent(type="text", text=f"Unknown tool: {name}")]
 
+    except ArgumentError as e:
+        return [TextContent(type="text", text=f"Error: {e}")]
     except Exception as e:
         logger.exception(f"Error executing tool {name}: {e}")
         return [TextContent(type="text", text=f"Error: {str(e)}")]
@@ -665,11 +717,9 @@
     """Run the MCP server."""
     logger.info("Starting Binwalk MCP Server")
     logger.info(f"Output directory: {settings.output_dir}")
-    logger.info(f"Upload directory: {settings.upload_dir}")
 
     # Ensure directories exist
     Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
-    Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)
 
     async with stdio_server() as (read_stream, write_stream):
         await app.run(read_stream, write_stream, app.create_initialization_options())
```
