# nmap - provenance and audit

| | |
|---|---|
| MCP server | FuzzingLabs mcp-security-hub, `reconnaissance/nmap-mcp/server.py` |
| Upstream | https://github.com/FuzzingLabs/mcp-security-hub (removed from GitHub); authentic copy https://github.com/D4T4HUN73R/mcp-security-hub |
| Commit | `0409a5435666f6381d9057807e949cf02d98e8db` (2026-01-27) |
| Wrapper licence | MIT, Copyright (c) 2025 Fuzzing Labs (`LICENSES/FuzzingLabs-mcp-security-hub-MIT.txt`) |
| Tool | Nmap 7.95, Debian trixie package `nmap=7.95+dfsg-3` |
| Tool licence | Nmap licence as shipped by Debian ("nmap-GPL-2": GPL-2.0 with Nmap's clarifications), `LICENSES/debian-nmap-copyright.txt` |
| Python packages | `requirements.txt` (hash-locked, generated from `requirements.in` by `scripts/lock.sh`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools:** `port_scan`, `service_scan`, `script_scan`, `quick_scan`, `get_scan_results`,
`list_active_scans`. Upstream also had `os_detection` (removed, see below).

**Command execution:** nmap is started with `asyncio.create_subprocess_exec` and an argument
list - no shell. Upstream passed the arguments into that list unchecked:

- `target` was appended as the last argument, so a value starting with `-` became an nmap
  option (`-iL <file>` reads a target list, `-oN <file>` writes files, `--script <file>` runs
  Lua, `--resume`, `--datadir`, ...);
- `timing` was formatted into `-T{timing}` without a type check;
- `scripts` were joined into `--script` unchecked (paths to `.nse` files and boolean
  expressions were possible);
- `ports` and `timeout` were not checked or bounded.

**Network:** needs to reach the scanned hosts on arbitrary ports, so axross's network must be
Full (the allowlist proxy only carries HTTPS CONNECT).

**Raw sockets:** axross runs servers with `--cap-drop=ALL`, so there is no `NET_RAW`. Upstream
used a SYN scan (`-sS`) for `port_scan` and `-O` for OS detection; both need raw sockets.
When axross mounts a folder it runs the container as its root, and nmap then *assumes*
privileges and fails. Fixed: every scan runs with `--unprivileged`, `port_scan` uses a TCP
connect scan (`-sT`), and `os_detection` is not offered. UDP port specs (`U:`) are accepted
by the validator but need a UDP scan, which is not offered either.

**Files:** writes nmap's XML and text output to `/tmp/nmap-mcp` (tmpfs); reads no user files.

**Bug found while testing:** a connect scan of a port nmap has no service name for produces a
`<port>` without a `<service>` element (checked with nmap 7.95: `<port protocol="tcp"
portid="18089"><state state="open" .../></port>`). The parser stores `"service": None`, and
the summary called `p.get("service", {}).get("name")` on it: every such `port_scan` failed
with `'NoneType' object has no attribute 'get'`. Fixed in `format_scan_summary`.

**Licence note:** Nmap's licence counts a program "designed specifically to execute Covered
Software and parse the results" as a derivative work that must follow the GPL terms
(source of the whole work available, free redistribution). This wrapper is MIT
(GPL-compatible) and fully published here; nmap itself is Debian's unmodified package, whose
source is available from Debian (`apt-get source nmap=7.95+dfsg-3`).

## Local patches

`src/server.py` is the upstream file with this patch (also summarized in its docstring):

- strict validation of `target` (host name, IPv4/IPv6 address, CIDR or octet range; never a
  leading `-`), `ports`, `scripts` (NSE names or categories only), `timing` (0-5) and
  `timeout` (1-3600 s); a refused argument returns `Error: <why>`;
- `--unprivileged` on every scan, `-sT` instead of `-sS`, `os_detection` removed;
- output under `/tmp/nmap-mcp` (the image's root file system is read-only);
- results kept in memory are bounded (100);
- the `format_scan_summary` crash above.

### The patch (unified diff against the upstream file, +87 / -68 lines)

```diff
--- a/reconnaissance/nmap-mcp/server.py (FuzzingLabs 0409a54)
+++ b/servers/nmap/src/server.py
@@ -8,10 +8,14 @@
 Tools:
     - port_scan: Scan ports on a target
     - service_scan: Detect service versions
-    - os_detection: Fingerprint operating system
     - script_scan: Run NSE scripts
     - quick_scan: Fast scan of common ports
     - get_scan_results: Retrieve previous scan results
+
+axross-mcp-hub patch: the container runs without capabilities (no NET_RAW), so
+every scan is an unprivileged TCP connect scan (-sT --unprivileged) and OS
+detection (-O, raw packets) is not offered. Every argument is validated before
+it reaches nmap's command line, so no value can become an nmap option.
 """
 
 import asyncio
@@ -46,7 +50,7 @@
 class Settings(BaseSettings):
     """Server configuration from environment variables."""
 
-    output_dir: str = Field(default="/app/output", alias="NMAP_OUTPUT_DIR")
+    output_dir: str = Field(default="/tmp/nmap-mcp", alias="NMAP_OUTPUT_DIR")
     default_timeout: int = Field(default=300, alias="NMAP_TIMEOUT")
     max_concurrent_scans: int = Field(default=3, alias="NMAP_MAX_CONCURRENT")
 
@@ -75,6 +79,62 @@
 # In-memory storage for scan results
 scan_results: dict[str, ScanResult] = {}
 active_scans: set[str] = set()
+#: Results kept in memory (the oldest are dropped).
+MAX_STORED_RESULTS = 100
+MAX_TIMEOUT = 3600
+
+# A target is a host name, an IPv4/IPv6 address, a CIDR range or an nmap octet
+# range (192.0.2.1-20); it never starts with "-", so it cannot become an option.
+_TARGET = re.compile(r"^[A-Za-z0-9:\[][A-Za-z0-9.:/_\-\[\]]{0,252}$")
+# Port lists: 22,80,443 / 1-1000 / T:21-25,80
+_PORTS = re.compile(r"^[0-9TU:][0-9TU:,\-]{0,254}$")
+# NSE script names or categories (no paths, no boolean expressions)
+_SCRIPT = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,63}$")
+
+
+class ArgumentError(ValueError):
+    """A tool argument that is not accepted; the text says why."""
+
+
+def _target(value) -> str:
+    if not isinstance(value, str) or not _TARGET.match(value):
+        raise ArgumentError("target: a host name, IP address or CIDR range (letters, digits, . : / - [ ])")
+    return value
+
+
+def _ports(value) -> str | None:
+    if value is None or value == "":
+        return None
+    if not isinstance(value, str) or not _PORTS.match(value):
+        raise ArgumentError("ports: digits, ',', '-' and T:/U: prefixes only (e.g. 22,80,443 or 1-1000)")
+    return value
+
+
+def _scripts(value) -> list[str] | None:
+    if value is None:
+        return None
+    if not isinstance(value, list) or len(value) > 32 or not all(
+        isinstance(v, str) and _SCRIPT.match(v) for v in value
+    ):
+        raise ArgumentError("scripts: up to 32 NSE script names or categories (e.g. http-title, default)")
+    return value
+
+
+def _int(value, name: str, low: int, high: int, default: int | None) -> int | None:
+    if value is None:
+        return default
+    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
+        raise ArgumentError(f"{name}: an integer from {low} to {high}")
+    return value
+
+
+def _remember(scan_id: str, result: "ScanResult") -> None:
+    scan_results[scan_id] = result
+    while len(scan_results) > MAX_STORED_RESULTS:
+        oldest = next(iter(scan_results))
+        if oldest in active_scans:
+            break
+        del scan_results[oldest]
 
 
 def parse_nmap_xml(xml_path: Path) -> dict[str, Any]:
@@ -202,22 +262,20 @@
         scan_type=scan_type,
         started_at=datetime.now(),
     )
-    scan_results[scan_id] = result
+    _remember(scan_id, result)
     active_scans.add(scan_id)
 
-    # Build nmap command
-    cmd = ["nmap", "-oX", str(xml_output), "-oN", str(txt_output)]
+    # Build nmap command; --unprivileged: never raw sockets (no NET_RAW in the container)
+    cmd = ["nmap", "--unprivileged", "-oX", str(xml_output), "-oN", str(txt_output)]
 
     # Add timing template
     cmd.append(f"-T{timing}")
 
     # Add scan type specific options
     if scan_type == "port":
-        cmd.append("-sS")  # SYN scan (requires root/cap)
+        cmd.append("-sT")  # TCP connect scan (a SYN scan needs NET_RAW)
     elif scan_type == "service":
         cmd.extend(["-sV", "--version-intensity", "5"])
-    elif scan_type == "os":
-        cmd.append("-O")
     elif scan_type == "script":
         cmd.append("-sC")  # Default scripts
         if scripts:
@@ -286,7 +344,6 @@
 
     finally:
         active_scans.discard(scan_id)
-        scan_results[scan_id] = result
 
     return result
 
@@ -313,11 +370,13 @@
                 {
                     "port": p.get("port"),
                     "protocol": p.get("protocol"),
-                    "service": p.get("service", {}).get("name"),
-                    "version": p.get("service", {}).get("version"),
+                    # a port without a <service> element (a plain connect scan of an
+                    # unknown port) is parsed as "service": None
+                    "service": (p.get("service") or {}).get("name"),
+                    "version": (p.get("service") or {}).get("version"),
                 }
                 for p in host.get("ports", [])
-                if p.get("state", {}).get("state") == "open"
+                if (p.get("state") or {}).get("state") == "open"
             ],
         }
         host_summaries.append(host_summary)
@@ -337,7 +396,7 @@
         Tool(
             name="port_scan",
             description="Scan ports on a target host or network. "
-            "Discovers open ports using SYN scan.",
+            "Discovers open ports using a TCP connect scan.",
             inputSchema={
                 "type": "object",
                 "properties": {
@@ -390,26 +449,6 @@
             },
         ),
         Tool(
-            name="os_detection",
-            description="Fingerprint the operating system of the target. "
-            "Requires at least one open and one closed port.",
-            inputSchema={
-                "type": "object",
-                "properties": {
-                    "target": {
-                        "type": "string",
-                        "description": "Target IP or hostname",
-                    },
-                    "timeout": {
-                        "type": "integer",
-                        "description": "Scan timeout in seconds",
-                        "default": 300,
-                    },
-                },
-                "required": ["target"],
-            },
-        ),
-        Tool(
             name="script_scan",
             description="Run NSE (Nmap Scripting Engine) scripts against target. "
             "Scripts can detect vulnerabilities, gather information, and more.",
@@ -496,11 +535,11 @@
                 ]
 
             result = await run_nmap_scan(
-                target=arguments["target"],
+                target=_target(arguments.get("target")),
                 scan_type="port",
-                ports=arguments.get("ports"),
-                timing=arguments.get("timing", 3),
-                timeout=arguments.get("timeout"),
+                ports=_ports(arguments.get("ports")),
+                timing=_int(arguments.get("timing"), "timing", 0, 5, 3),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -520,32 +559,10 @@
                 ]
 
             result = await run_nmap_scan(
-                target=arguments["target"],
+                target=_target(arguments.get("target")),
                 scan_type="service",
-                ports=arguments.get("ports"),
-                timeout=arguments.get("timeout"),
-            )
-
-            return [
-                TextContent(
-                    type="text",
-                    text=json.dumps(format_scan_summary(result), indent=2),
-                )
-            ]
-
-        elif name == "os_detection":
-            if len(active_scans) >= settings.max_concurrent_scans:
-                return [
-                    TextContent(
-                        type="text",
-                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
-                    )
-                ]
-
-            result = await run_nmap_scan(
-                target=arguments["target"],
-                scan_type="os",
-                timeout=arguments.get("timeout"),
+                ports=_ports(arguments.get("ports")),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -565,11 +582,11 @@
                 ]
 
             result = await run_nmap_scan(
-                target=arguments["target"],
+                target=_target(arguments.get("target")),
                 scan_type="script",
-                scripts=arguments.get("scripts"),
-                ports=arguments.get("ports"),
-                timeout=arguments.get("timeout"),
+                scripts=_scripts(arguments.get("scripts")),
+                ports=_ports(arguments.get("ports")),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -589,7 +606,7 @@
                 ]
 
             result = await run_nmap_scan(
-                target=arguments["target"],
+                target=_target(arguments.get("target")),
                 scan_type="quick",
                 timing=4,
                 timeout=120,
@@ -603,7 +620,7 @@
             ]
 
         elif name == "get_scan_results":
-            scan_id = arguments["scan_id"]
+            scan_id = str(arguments.get("scan_id", ""))
             result = scan_results.get(scan_id)
 
             if result:
@@ -650,6 +667,8 @@
         else:
             return [TextContent(type="text", text=f"Unknown tool: {name}")]
 
+    except ArgumentError as e:
+        return [TextContent(type="text", text=f"Error: {e}")]
     except Exception as e:
         logger.exception(f"Error executing tool {name}: {e}")
         return [TextContent(type="text", text=f"Error: {str(e)}")]
```
