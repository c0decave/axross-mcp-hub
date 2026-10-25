# nuclei - provenance and audit

| | |
|---|---|
| MCP server | FuzzingLabs mcp-security-hub, `web-security/nuclei-mcp/server.py` |
| Upstream | https://github.com/FuzzingLabs/mcp-security-hub (removed from GitHub); authentic copy https://github.com/D4T4HUN73R/mcp-security-hub |
| Commit | `0409a5435666f6381d9057807e949cf02d98e8db` (2026-01-27) |
| Wrapper licence | MIT, Copyright (c) 2025 Fuzzing Labs (`LICENSES/FuzzingLabs-mcp-security-hub-MIT.txt`) |
| Tool | ProjectDiscovery nuclei 3.11.1, release archive `nuclei_3.11.1_linux_<arch>.zip`, checked against the SHA-256 of the release's `nuclei_3.11.1_checksums.txt` (amd64 `ea63d4ae...5ab6`, arm64 `8044e3d9...bec07`) |
| Templates | https://github.com/projectdiscovery/nuclei-templates at `79fb682760ab3d5b0e22afbb44709353cbebf023` (tag v10.5.1) |
| Tool licence | MIT (`LICENSES/nuclei-LICENSE.md`, `LICENSES/nuclei-templates-LICENSE.md`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools:** `nuclei_scan`, `quick_scan`, `template_scan`, `list_templates`,
`get_scan_results`, `list_active_scans`.

**Command execution:** `nuclei` is started with `asyncio.create_subprocess_exec` and an
argument list - no shell. The target is the value of `-target`, but upstream did not check
it, nor the `tags`, `severity` and `templates` lists joined into `-tags` / `-severity`, nor
`rate_limit` and `timeout`. Code templates (`-code`) and headless templates stay off (nuclei's
default; the server never passes those flags).

**Network:** the targets, so axross's network must be Full.

**Out-of-band traffic:** nuclei uses interactsh by default: for out-of-band checks it
registers with a public interactsh server (oast.*) and makes the target call it, which sends
information about the target to a third party. The server now passes `-no-interactsh`.

**Templates:** upstream's image had an empty templates folder; nuclei then downloads the
templates on first start (network, a writable home) and checks for updates on every run.
The image now carries a pinned templates release and nuclei runs with
`-disable-update-check`.

**Bug fixed:** `template_scan` passed category names (`cves`, `technologies`, ...) as tags;
the templates are tagged `cve`, `tech`, ..., so most categories matched nothing. Categories now
select their template folders (`http/cves`, `http/technologies`, `network`, `ssl`, `dns`, ...);
`headless` (needs a browser) and `file` (scans local files) are not offered.

**Memory:** a scan with every template can exceed axross's fixed 512 MiB limit [not
measured]; a `misconfiguration` category scan of a test target finished in about three
minutes within the limit.

**Known vulnerabilities (Trivy 0.76.1, local scan 2026-10-25):** no CRITICAL; 25 HIGH with
fixes available, all in Go modules compiled into the nuclei 3.11.1 binary (e.g.
`github.com/getkin/kin-openapi`, `github.com/go-git/go-git/v5`, `golang.org/x/crypto`). They
go away only with a nuclei release built against newer modules; 3.11.1 is the latest release
at the time of writing.

## Local patches

- `target`: an http(s) URL or host[:port], never a leading `-`, no whitespace; `tags`,
  `severity`, `templates`: lists of known or well-formed names; `rate_limit` 1-1000,
  `timeout` 1-3600 s; refused arguments return `Error: <why>`;
- `-disable-update-check -no-interactsh -no-color` on every scan; the pinned templates at
  `/opt/nuclei-templates`;
- categories select template folders (bug above);
- results kept in memory are bounded (100); output under `/tmp/nuclei-mcp`.

### The patch (unified diff against the upstream file, +121 / -40 lines)

```diff
--- a/web-security/nuclei-mcp/server.py (FuzzingLabs 0409a54)
+++ b/servers/nuclei/src/server.py
@@ -12,6 +12,13 @@
     - list_templates: List available template categories
     - get_scan_results: Retrieve previous scan results
     - list_active_scans: Show running scans
+
+axross-mcp-hub patch: targets, tags and severities are validated before they reach
+nuclei's command line; the templates are the pinned set baked into the image
+(no update check, no download at start); interactsh (out-of-band callbacks to a
+third-party server) is off; template categories select template folders (they
+were passed as tags before, which matched nothing); numbers are range-checked and
+stored results are bounded.
 """
 
 import asyncio
@@ -45,8 +52,8 @@
 class Settings(BaseSettings):
     """Server configuration from environment variables."""
 
-    templates_dir: str = Field(default="/home/mcpuser/nuclei-templates", alias="NUCLEI_TEMPLATES_PATH")
-    output_dir: str = Field(default="/app/output", alias="NUCLEI_OUTPUT_DIR")
+    templates_dir: str = Field(default="/opt/nuclei-templates", alias="NUCLEI_TEMPLATES_PATH")
+    output_dir: str = Field(default="/tmp/nuclei-mcp", alias="NUCLEI_OUTPUT_DIR")
     default_timeout: int = Field(default=600, alias="NUCLEI_TIMEOUT")
     max_concurrent_scans: int = Field(default=2, alias="NUCLEI_MAX_CONCURRENT")
     rate_limit: int = Field(default=150, alias="NUCLEI_RATE_LIMIT")
@@ -91,26 +98,97 @@
 scan_results: dict[str, ScanResult] = {}
 active_scans: set[str] = set()
 
-# Template categories
-TEMPLATE_CATEGORIES = [
-    "cves",
-    "vulnerabilities",
-    "exposures",
-    "misconfiguration",
-    "technologies",
-    "default-logins",
-    "takeovers",
-    "file",
-    "fuzzing",
-    "headless",
-    "iot",
-    "network",
-    "ssl",
-    "dns",
-]
+# Template categories: the template folders they select (headless needs a browser
+# and file templates scan local files, so neither is offered)
+CATEGORY_PATHS = {
+    "cves": "http/cves",
+    "vulnerabilities": "http/vulnerabilities",
+    "exposures": "http/exposures",
+    "misconfiguration": "http/misconfiguration",
+    "technologies": "http/technologies",
+    "default-logins": "http/default-logins",
+    "takeovers": "http/takeovers",
+    "fuzzing": "http/fuzzing",
+    "iot": "http/iot",
+    "network": "network",
+    "ssl": "ssl",
+    "dns": "dns",
+}
+TEMPLATE_CATEGORIES = list(CATEGORY_PATHS)
 
 SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
 
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
+# http(s)://host[:port][/path] or host[:port]; never starts with "-", no whitespace
+_TARGET = re.compile(r"^(?:https?://)?[A-Za-z0-9\[][A-Za-z0-9.\-_:\[\]]{0,253}(?:/[^\s]{0,2000})?$")
+_TAG = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,63}$")
+
+
+def _target(value) -> str:
+    if not isinstance(value, str) or not _TARGET.match(value):
+        raise ArgumentError("target: a URL (http:// or https://) or host[:port]")
+    return value
+
+
+def _names(value, what: str, allowed=None) -> list[str] | None:
+    if value is None:
+        return None
+    if not isinstance(value, list) or len(value) > 64 or not all(
+        isinstance(v, str) and _TAG.match(v) and (allowed is None or v in allowed) for v in value
+    ):
+        hint = f"one of {', '.join(allowed)}" if allowed else "letters, digits, '.', '_' and '-'"
+        raise ArgumentError(f"{what}: a list of names ({hint})")
+    return value
+
 
 def parse_nuclei_jsonl(output: str) -> list[Finding]:
     """Parse nuclei JSONL output into findings."""
@@ -184,7 +262,7 @@
         scan_type=scan_type,
         started_at=datetime.now(),
     )
-    scan_results[scan_id] = result
+    _remember(scan_results, scan_id, result, active_scans)
     active_scans.add(scan_id)
 
     # Build nuclei command
@@ -195,20 +273,22 @@
         "-output", str(output_file),
         "-rate-limit", str(rate_limit or settings.rate_limit),
         "-silent",
+        "-disable-update-check",  # the templates are pinned in the image
+        "-no-interactsh",         # no out-of-band callbacks to a third-party server
+        "-no-color",
     ]
 
-    # Add templates path if exists
-    if Path(settings.templates_dir).exists():
-        cmd.extend(["-templates", settings.templates_dir])
-
     # Add scan type specific options
+    if scan_type == "template" and templates:
+        # Specific categories: their template folders
+        for category in templates:
+            cmd.extend(["-templates", str(Path(settings.templates_dir) / CATEGORY_PATHS[category])])
+    else:
+        cmd.extend(["-templates", settings.templates_dir])
     if scan_type == "quick":
         # Quick scan: only high/critical, common templates
         cmd.extend(["-severity", "high,critical"])
         cmd.extend(["-tags", "cve,rce,lfi,xss,sqli,ssrf"])
-    elif scan_type == "template" and templates:
-        # Specific templates/categories
-        cmd.extend(["-tags", ",".join(templates)])
     elif scan_type == "full":
         # Full scan with all templates
         pass  # No additional filters
@@ -287,7 +367,6 @@
 
     finally:
         active_scans.discard(scan_id)
-        scan_results[scan_id] = result
 
     return result
 
@@ -471,12 +550,12 @@
                 ]
 
             result = await run_nuclei_scan(
-                target=arguments["target"],
+                target=_target(arguments.get("target")),
                 scan_type="scan",
-                severity=arguments.get("severity"),
-                tags=arguments.get("tags"),
-                rate_limit=arguments.get("rate_limit"),
-                timeout=arguments.get("timeout"),
+                severity=_names(arguments.get("severity"), "severity", SEVERITY_LEVELS),
+                tags=_names(arguments.get("tags"), "tags"),
+                rate_limit=_int(arguments.get("rate_limit"), "rate_limit", 1, 1000, None),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -496,9 +575,9 @@
                 ]
 
             result = await run_nuclei_scan(
-                target=arguments["target"],
+                target=_target(arguments.get("target")),
                 scan_type="quick",
-                timeout=arguments.get("timeout", 300),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, 300),
             )
 
             return [
@@ -518,11 +597,11 @@
                 ]
 
             result = await run_nuclei_scan(
-                target=arguments["target"],
+                target=_target(arguments.get("target")),
                 scan_type="template",
-                templates=arguments.get("templates"),
-                severity=arguments.get("severity"),
-                timeout=arguments.get("timeout"),
+                templates=_names(arguments.get("templates"), "templates", TEMPLATE_CATEGORIES),
+                severity=_names(arguments.get("severity"), "severity", SEVERITY_LEVELS),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -552,7 +631,7 @@
             ]
 
         elif name == "get_scan_results":
-            scan_id = arguments["scan_id"]
+            scan_id = str(arguments.get("scan_id", ""))
             result = scan_results.get(scan_id)
 
             if result:
@@ -599,6 +678,8 @@
         else:
             return [TextContent(type="text", text=f"Unknown tool: {name}")]
 
+    except ArgumentError as e:
+        return [TextContent(type="text", text=f"Error: {e}")]
     except Exception as e:
         logger.exception(f"Error executing tool {name}: {e}")
         return [TextContent(type="text", text=f"Error: {str(e)}")]
```
