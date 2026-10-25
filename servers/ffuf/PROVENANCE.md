# ffuf - provenance and audit

| | |
|---|---|
| MCP server | FuzzingLabs mcp-security-hub, `web-security/ffuf-mcp/server.py` |
| Upstream | https://github.com/FuzzingLabs/mcp-security-hub (removed from GitHub); authentic copy https://github.com/D4T4HUN73R/mcp-security-hub |
| Commit | `0409a5435666f6381d9057807e949cf02d98e8db` (2026-01-27) |
| Wrapper licence | MIT, Copyright (c) 2025 Fuzzing Labs (`LICENSES/FuzzingLabs-mcp-security-hub-MIT.txt`) |
| Tool | ffuf 2.1.0, Debian trixie package `ffuf=2.1.0-1+b9` (MIT, `LICENSES/debian-ffuf-copyright.txt`) |
| Wordlists | SecLists (MIT, `LICENSES/SecLists-MIT.txt`) commit `ab068333d7d44a9376e2037b0ed7d2e8ca5c6610`: `Discovery/Web-Content/{common,raft-small-directories,raft-small-files,burp-parameter-names}.txt`, `Discovery/DNS/subdomains-top1million-5000.txt`, each checked against its sha256 in the Dockerfile |
| Python packages | `requirements.txt` (hash-locked, generated from `requirements.in` by `scripts/lock.sh`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools:** `ffuf_dir`, `ffuf_vhost`, `ffuf_param`, `ffuf_custom`, `list_wordlists`,
`get_fuzz_results`, `list_active_scans`.

**Command execution:** `asyncio.create_subprocess_exec` with an argument list - no shell;
each value is its own argument after its option (`-u URL`, `-w FILE`, `-H "K: V"`, ...), so
values cannot become options. Upstream checked none of them, though:

- **Wordlist = any file in the container.** `get_wordlist_path` returned any path that
  existed. ffuf sends every line of the wordlist to the target as part of a request, so a
  "wordlist" such as `/proc/self/environ` - where axross puts secret environment
  variables - or any other container file would be sent to a server the model chose.
- Header names and values, `data` and the URL could contain newlines; `method` was any
  string; `threads`, `rate`, `timeout`, `filter_*` and status codes were not type-checked or
  bounded; results were kept without limit.
- **Did not work under axross:** results were written to `/app/output` and wordlists were
  expected under `/app/wordlists/...` (dirb, dirbuster, full SecLists) - with axross's
  read-only root nothing could be written, and the named wordlists did not exist in this
  image.

**Fixed:** `url` must be `http(s)://` without whitespace; header names must be RFC 7230
tokens and values single lines (at most 32 headers); `method` 3-10 letters; `extensions`
at most 30 of `^\.?[A-Za-z0-9_-]{1,15}$`; status codes 100-599; `threads` 1-100, `rate`
0-10000, `timeout` 1-3600 s; `domain` a domain name; `data` one line. A wordlist is one of
the bundled names (`common`, `raft-small-dirs`, `raft-small-files`, `subdomains-top1mil`,
`params-top`) or a file that resolves under `/work`. Output goes to `/tmp/ffuf-mcp`
(tmpfs); at most 100 results are kept. The tool descriptions list the bundled wordlists
that really exist (upstream named ones that were never in the image).

**Network:** needs to reach the target, so axross's network must be Full.

## Local patches

`src/server.py` is the upstream file with this patch (also summarized in its docstring).

### The patch (unified diff against the upstream file, +155 / -56 lines)

```diff
--- a/web-security/ffuf-mcp/server.py (FuzzingLabs 0409a54)
+++ b/servers/ffuf/src/server.py
@@ -13,11 +13,18 @@
     - get_fuzz_results: Retrieve previous fuzzing results
     - list_active_scans: Show running scans
     - list_wordlists: List available wordlists
+
+axross-mcp-hub patch: every argument is validated before it reaches ffuf's command
+line (an http(s) URL, header names and single-line values, method, extensions, status
+codes, numbers); wordlists are the bundled SecLists files or files under /work (any
+container path could be sent to the target before); stored results are bounded.
 """
 
 import asyncio
 import json
 import logging
+import os
+import re
 import uuid
 from datetime import datetime
 from pathlib import Path
@@ -44,8 +51,8 @@
 class Settings(BaseSettings):
     """Server configuration from environment variables."""
 
-    output_dir: str = Field(default="/app/output", alias="FFUF_OUTPUT_DIR")
-    wordlists_dir: str = Field(default="/app/wordlists", alias="FFUF_WORDLISTS_DIR")
+    output_dir: str = Field(default="/tmp/ffuf-mcp", alias="FFUF_OUTPUT_DIR")
+    wordlists_dir: str = Field(default="/opt/wordlists", alias="FFUF_WORDLISTS_DIR")
     default_timeout: int = Field(default=600, alias="FFUF_TIMEOUT")
     max_concurrent_scans: int = Field(default=2, alias="FFUF_MAX_CONCURRENT")
     default_threads: int = Field(default=40, alias="FFUF_THREADS")
@@ -91,17 +98,111 @@
 scan_results: dict[str, ScanResult] = {}
 active_scans: set[str] = set()
 
-# Common wordlists
+# Common wordlists (SecLists files bundled in the image)
 WORDLISTS = {
-    "common": "/app/wordlists/common.txt",
-    "dirb-common": "/app/wordlists/dirb/common.txt",
-    "dirbuster-medium": "/app/wordlists/dirbuster/directory-list-2.3-medium.txt",
-    "raft-large-dirs": "/app/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt",
-    "raft-large-files": "/app/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt",
-    "subdomains-top1mil": "/app/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
-    "params-top": "/app/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
+    "common": "/opt/wordlists/common.txt",
+    "raft-small-dirs": "/opt/wordlists/raft-small-directories.txt",
+    "raft-small-files": "/opt/wordlists/raft-small-files.txt",
+    "subdomains-top1mil": "/opt/wordlists/subdomains-top1million-5000.txt",
+    "params-top": "/opt/wordlists/burp-parameter-names.txt",
 }
 
+# --- axross-mcp-hub: argument checks --------------------------------------------------
+INPUT_ROOTS = tuple(p for p in os.environ.get("MCP_INPUT_ROOTS", "/work").split(":") if p)
+MAX_STORED_RESULTS = 100
+MAX_TIMEOUT = 3600
+_URL = re.compile(r"^https?://[^\s]{1,2040}$")
+_HEADER = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
+_METHOD = re.compile(r"^[A-Z]{3,10}$")
+_EXTENSION = re.compile(r"^\.?[A-Za-z0-9_-]{1,15}$")
+_DOMAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
+
+
+class ArgumentError(ValueError):
+    """A tool argument that is not accepted; the text says why."""
+
+
+def _url(value, need_fuzz: bool = True) -> str:
+    if not isinstance(value, str) or not _URL.match(value):
+        raise ArgumentError("url: an http:// or https:// URL without spaces")
+    return value
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
+def _codes(value, name: str):
+    if value is None:
+        return None
+    if not isinstance(value, list) or len(value) > 50 or not all(
+            isinstance(c, int) and not isinstance(c, bool) and 100 <= c <= 599 for c in value):
+        raise ArgumentError(f"{name}: a list of HTTP status codes (100-599)")
+    return value
+
+
+def _line(value, name: str, limit: int = 8192):
+    if value is None or value == "":
+        return None
+    if not isinstance(value, str) or len(value) > limit or any(c in value for c in "\r\n\x00"):
+        raise ArgumentError(f"{name}: one line of at most {limit} characters")
+    return value
+
+
+def _headers(value):
+    if value is None:
+        return None
+    if not isinstance(value, dict) or len(value) > 32:
+        raise ArgumentError("headers: an object of at most 32 header names and values")
+    for key, val in value.items():
+        if not _HEADER.match(str(key)):
+            raise ArgumentError(f"headers: {key!r} is not a header name")
+        _line(val if isinstance(val, str) else None, f"headers {key}", 4096)
+    return value
+
+
+def _method(value) -> str:
+    value = value or "GET"
+    if not isinstance(value, str) or not _METHOD.match(value.upper()):
+        raise ArgumentError("method: an HTTP method such as GET or POST")
+    return value.upper()
+
+
+def _extensions(value):
+    if value is None:
+        return None
+    if not isinstance(value, list) or len(value) > 30 or not all(
+            isinstance(e, str) and _EXTENSION.match(e) for e in value):
+        raise ArgumentError("extensions: a list such as [\".php\", \".bak\"]")
+    return value
+
+
+def _wordlist(value) -> str:
+    """A bundled wordlist name or a file under /work."""
+    if isinstance(value, str) and value in WORDLISTS:
+        return value
+    roots = [os.path.realpath(r) for r in INPUT_ROOTS]
+    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
+        raise ArgumentError(f"wordlist: one of {', '.join(WORDLISTS)} or a file under /work")
+    path = os.path.realpath(value if os.path.isabs(value) else os.path.join(roots[0], value))
+    if not any(path.startswith(r.rstrip("/") + "/") for r in roots) or not os.path.isfile(path):
+        raise ArgumentError(f"wordlist: one of {', '.join(WORDLISTS)} or a file under /work")
+    return path
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
 
 def parse_ffuf_json(output: str) -> list[FuzzResult]:
     """Parse ffuf JSON output."""
@@ -128,14 +229,8 @@
 
 
 def get_wordlist_path(wordlist: str) -> str:
-    """Get full path for a wordlist."""
-    if wordlist in WORDLISTS:
-        return WORDLISTS[wordlist]
-    elif Path(wordlist).exists():
-        return wordlist
-    elif Path(settings.wordlists_dir, wordlist).exists():
-        return str(Path(settings.wordlists_dir, wordlist))
-    return wordlist
+    """Get full path for a wordlist (a bundled name or a path checked by _wordlist)."""
+    return WORDLISTS.get(wordlist, wordlist)
 
 
 async def run_ffuf(
@@ -164,8 +259,9 @@
         fuzz_type=fuzz_type,
         started_at=datetime.now(),
     )
-    scan_results[scan_id] = result
+    _remember(scan_results, scan_id, result, active_scans)
     active_scans.add(scan_id)
+    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
 
     # Build ffuf command
     wordlist_path = get_wordlist_path(wordlist)
@@ -274,7 +370,6 @@
 
     finally:
         active_scans.discard(scan_id)
-        scan_results[scan_id] = result
 
     return result
 
@@ -323,7 +418,7 @@
                     },
                     "wordlist": {
                         "type": "string",
-                        "description": "Wordlist to use (common, dirb-common, dirbuster-medium, raft-large-dirs, or path)",
+                        "description": "Wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                         "default": "common",
                     },
                     "extensions": {
@@ -367,7 +462,7 @@
                     },
                     "wordlist": {
                         "type": "string",
-                        "description": "Subdomain wordlist to use",
+                        "description": "Subdomain wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                         "default": "subdomains-top1mil",
                     },
                     "filter_size": {
@@ -401,7 +496,7 @@
                     },
                     "wordlist": {
                         "type": "string",
-                        "description": "Parameter wordlist to use",
+                        "description": "Parameter wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                         "default": "params-top",
                     },
                     "method": {
@@ -445,7 +540,7 @@
                     },
                     "wordlist": {
                         "type": "string",
-                        "description": "Wordlist path or name",
+                        "description": "Wordlist: a bundled one (common, raft-small-dirs, raft-small-files, subdomains-top1mil, params-top) or a file under /work",
                     },
                     "method": {
                         "type": "string",
@@ -542,18 +637,18 @@
                     )
                 ]
 
-            url = arguments["url"]
+            url = _url(arguments.get("url"))
             if "FUZZ" not in url:
                 url = url.rstrip("/") + "/FUZZ"
 
             result = await run_ffuf(
                 url=url,
-                wordlist=arguments.get("wordlist", "common"),
+                wordlist=_wordlist(arguments.get("wordlist", "common")),
                 fuzz_type="directory",
-                extensions=arguments.get("extensions"),
-                filter_codes=arguments.get("filter_codes", [404]),
-                threads=arguments.get("threads"),
-                timeout=arguments.get("timeout"),
+                extensions=_extensions(arguments.get("extensions")),
+                filter_codes=_codes(arguments.get("filter_codes", [404]), "filter_codes"),
+                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -572,17 +667,19 @@
                     )
                 ]
 
-            domain = arguments["domain"]
+            domain = arguments.get("domain")
+            if not isinstance(domain, str) or not _DOMAIN.match(domain):
+                raise ArgumentError("domain: a domain name such as example.com")
             headers = {"Host": f"FUZZ.{domain}"}
 
             result = await run_ffuf(
-                url=arguments["url"],
-                wordlist=arguments.get("wordlist", "subdomains-top1mil"),
+                url=_url(arguments.get("url")),
+                wordlist=_wordlist(arguments.get("wordlist", "subdomains-top1mil")),
                 fuzz_type="vhost",
                 headers=headers,
-                filter_size=arguments.get("filter_size"),
-                threads=arguments.get("threads"),
-                timeout=arguments.get("timeout"),
+                filter_size=_int(arguments.get("filter_size"), "filter_size", 0, 1 << 40, None),
+                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -602,14 +699,14 @@
                 ]
 
             result = await run_ffuf(
-                url=arguments["url"],
-                wordlist=arguments.get("wordlist", "params-top"),
+                url=_url(arguments.get("url")),
+                wordlist=_wordlist(arguments.get("wordlist", "params-top")),
                 fuzz_type="parameter",
-                method=arguments.get("method", "GET"),
-                data=arguments.get("data"),
-                filter_size=arguments.get("filter_size"),
-                threads=arguments.get("threads"),
-                timeout=arguments.get("timeout"),
+                method=_method(arguments.get("method", "GET")),
+                data=_line(arguments.get("data"), "data"),
+                filter_size=_int(arguments.get("filter_size"), "filter_size", 0, 1 << 40, None),
+                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -629,19 +726,19 @@
                 ]
 
             result = await run_ffuf(
-                url=arguments["url"],
-                wordlist=arguments["wordlist"],
+                url=_url(arguments.get("url")),
+                wordlist=_wordlist(arguments.get("wordlist")),
                 fuzz_type="custom",
-                method=arguments.get("method", "GET"),
-                headers=arguments.get("headers"),
-                data=arguments.get("data"),
-                match_codes=arguments.get("match_codes"),
-                filter_codes=arguments.get("filter_codes"),
-                filter_size=arguments.get("filter_size"),
-                filter_words=arguments.get("filter_words"),
-                threads=arguments.get("threads"),
-                rate=arguments.get("rate"),
-                timeout=arguments.get("timeout"),
+                method=_method(arguments.get("method", "GET")),
+                headers=_headers(arguments.get("headers")),
+                data=_line(arguments.get("data"), "data"),
+                match_codes=_codes(arguments.get("match_codes"), "match_codes"),
+                filter_codes=_codes(arguments.get("filter_codes"), "filter_codes"),
+                filter_size=_int(arguments.get("filter_size"), "filter_size", 0, 1 << 40, None),
+                filter_words=_int(arguments.get("filter_words"), "filter_words", 0, 1 << 30, None),
+                threads=_int(arguments.get("threads"), "threads", 1, 100, None),
+                rate=_int(arguments.get("rate"), "rate", 0, 10000, None),
+                timeout=_int(arguments.get("timeout"), "timeout", 1, MAX_TIMEOUT, None),
             )
 
             return [
@@ -679,7 +776,7 @@
             ]
 
         elif name == "get_fuzz_results":
-            scan_id = arguments["scan_id"]
+            scan_id = str(arguments.get("scan_id", ""))
             result = scan_results.get(scan_id)
 
             if result:
@@ -723,6 +820,8 @@
         else:
             return [TextContent(type="text", text=f"Unknown tool: {name}")]
 
+    except ArgumentError as e:
+        return [TextContent(type="text", text=f"Error: {e}")]
     except Exception as e:
         logger.exception(f"Error executing tool {name}: {e}")
         return [TextContent(type="text", text=f"Error: {str(e)}")]
```
