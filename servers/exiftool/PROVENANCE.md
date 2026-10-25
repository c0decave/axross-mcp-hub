# exiftool - provenance and audit

| | |
|---|---|
| MCP server | joshmsimpson/exiftool_mcp, `src/exiftool_mcp/server.py`, https://github.com/joshmsimpson/exiftool_mcp |
| Commit | `b83031573125a72c4593972350e444e5b4815949` (2025-10-02), fetched as tarball (sha256 `23574961bc26d6353311b7993f19a9bbaef4769b7d1d892e83517b5a457cc336`) |
| Server licence | MIT (`LICENSES/exiftool_mcp-MIT.txt`) |
| Tool | ExifTool 13.25, Debian trixie package `libimage-exiftool-perl=13.25+dfsg-1` |
| Tool licence | Artistic or GPL-1+ (as Perl), some files GPL-1+ or CC-BY-4.0, `LICENSES/debian-libimage-exiftool-perl-copyright.txt` |
| Python packages | `mcp==1.30.0` and its dependencies, hash-locked in `requirements.txt` |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

## Audit

**Tools (upstream):** `read_metadata`, `write_metadata`, `remove_metadata`,
`list_supported_formats`. **Offered here:** `read_metadata`, `list_supported_formats`.

**Command execution:** `asyncio.create_subprocess_exec("exiftool", *args)` - no shell. But
the arguments were built from model input unchecked:

- **Code execution through tag names.** `read_metadata` appended every requested tag as
  `-{tag}`. ExifTool treats any such argument as an option when it is one: the tag list
  `["if", "system('id')"]` becomes `-if -system('id')`, and `-if` *evaluates its next
  argument as Perl*. Reproduced with the image's ExifTool 13.25:
  `exiftool -json -a -G1 -if "-system('echo UPSTREAM-RCE-PROOF >&2')" /work/photo.png`
  prints `UPSTREAM-RCE-PROOF` (and "1 files failed condition"). Other tag names reach
  options that read argument files (`-@ FILE`), write output files (`-w`, `-o`) or change
  files in place.
- `write_metadata` passed tag names and values as `-{tag}={value}` arguments and changed
  the user's file (with `-overwrite_original` optional) - the same injection, plus writes;
  `remove_metadata` removed metadata in place.
- `file_path` was any path (`expanduser().resolve()`), i.e. any file in the container.

**Fixed:** requested tags no longer reach ExifTool's command line: ExifTool always runs as
`exiftool -json -a -G1 <absolute path>` and the tag list filters the JSON in Python
(case-insensitive, `*`/`?` wildcards, matching `Group:Tag` or the bare tag name; at most
200 names of up to 100 characters). `write_metadata` and `remove_metadata` are removed
(read-only server - folders are mounted read-only by default anyway). `file_path` must
resolve under `/work` and is passed absolute. Every ExifTool run has a 120 s timeout,
stdin is `/dev/null`, and answers are cut at 200,000 characters.

**Network:** none. **Files:** reads only the given file.

## Local patches

`src/server.py` is the upstream file with the changes above (also summarized in its
docstring).

### The patch (unified diff against the upstream file, +72 / -195 lines)

```diff
--- a/src/exiftool_mcp/server.py (joshmsimpson/exiftool_mcp b830315)
+++ b/servers/exiftool/src/server.py
@@ -1,9 +1,19 @@
 #!/usr/bin/env python3
-"""MCP server for reading, writing and removing file metadata using ExifTool."""
+"""MCP server for reading file metadata using ExifTool.
+
+axross-mcp-hub patch (upstream: joshmsimpson/exiftool_mcp): read-only. Files are read
+only from /work (the folder axross mounts) and passed as absolute paths; requested tags
+filter exiftool's JSON in Python instead of becoming "-TAG" arguments (a "tag" such as
+"if" became exiftool's -if option, which evaluates Perl); write_metadata and
+remove_metadata are not offered (they changed the user's files and passed tag names and
+values as exiftool arguments). Output is size-bounded.
+"""
 
 import asyncio
+import fnmatch
 import json
 import logging
+import os
 import shutil
 from pathlib import Path
 from typing import Any
@@ -18,6 +28,25 @@
 # Initialize MCP server
 app = Server("exiftool-mcp")
 
+#: axross-mcp-hub: files are read only from these folders (axross mounts /work).
+INPUT_ROOTS = tuple(p for p in os.environ.get("MCP_INPUT_ROOTS", "/work").split(":") if p)
+MAX_OUTPUT = 200_000
+TIMEOUT = 120
+
+
+def _input_path(value) -> Path:
+    """*value* as an absolute, symlink-free path of a file under INPUT_ROOTS, or ValueError."""
+    roots = [os.path.realpath(r) for r in INPUT_ROOTS]
+    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 4096:
+        raise ValueError(f"file_path: a path under {', '.join(INPUT_ROOTS)}")
+    path = os.path.realpath(value if os.path.isabs(value) else os.path.join(roots[0], value))
+    if not any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots):
+        raise ValueError(f"file_path: only files under {', '.join(INPUT_ROOTS)} are read "
+                         "(mount the folder there)")
+    if not os.path.isfile(path):
+        raise ValueError(f"File not found: {value}")
+    return Path(path)
+
 
 def check_exiftool_installed() -> bool:
     """Check if exiftool is installed and available in PATH."""
@@ -30,10 +59,16 @@
         process = await asyncio.create_subprocess_exec(
             "exiftool",
             *args,
+            stdin=asyncio.subprocess.DEVNULL,
             stdout=asyncio.subprocess.PIPE,
             stderr=asyncio.subprocess.PIPE,
         )
-        stdout, stderr = await process.communicate()
+        try:
+            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=TIMEOUT)
+        except asyncio.TimeoutError:
+            process.kill()
+            await process.wait()
+            return "", f"exiftool did not finish within {TIMEOUT} s", 1
         return (
             stdout.decode("utf-8", errors="replace"),
             stderr.decode("utf-8", errors="replace"),
@@ -43,69 +78,37 @@
         return "", "exiftool not found in PATH", 1
 
 
+def _select(metadata: dict, tags: list[str]) -> dict:
+    """The entries of *metadata* whose key ("Group:Tag") or tag name matches one of *tags*
+    (case-insensitive, * and ? as wildcards)."""
+    patterns = [t.lower() for t in tags]
+    out = {}
+    for key, value in metadata.items():
+        name = key.split(":", 1)[-1].lower()
+        if key == "SourceFile" or any(fnmatch.fnmatchcase(key.lower(), p) or
+                                      fnmatch.fnmatchcase(name, p) for p in patterns):
+            out[key] = value
+    return out
+
+
 @app.list_tools()
 async def list_tools() -> list[Tool]:
     """List available ExifTool tools."""
     return [
         Tool(
             name="read_metadata",
-            description="Read metadata from a file using ExifTool. Supports images, videos, audio files, PDFs, and many other formats. Returns detailed metadata including EXIF, IPTC, XMP, and format-specific information.",
-            inputSchema={
-                "type": "object",
-                "properties": {
-                    "file_path": {
-                        "type": "string",
-                        "description": "Path to the file to read metadata from (absolute or relative path)",
-                    },
-                    "tags": {
-                        "type": "array",
-                        "items": {"type": "string"},
-                        "description": "Optional: Specific metadata tags to extract (e.g., ['DateTimeOriginal', 'Make', 'Model']). If not specified, all metadata is returned.",
-                    },
-                },
-                "required": ["file_path"],
-            },
-        ),
-        Tool(
-            name="write_metadata",
-            description="Write or update metadata tags in a file using ExifTool. Creates a backup by default. Can set multiple tags at once.",
-            inputSchema={
-                "type": "object",
-                "properties": {
-                    "file_path": {
-                        "type": "string",
-                        "description": "Path to the file to write metadata to (absolute or relative path)",
-                    },
-                    "tags": {
-                        "type": "object",
-                        "description": "Metadata tags to write as key-value pairs (e.g., {'Artist': 'John Doe', 'Copyright': '2025'})",
-                    },
-                    "overwrite_original": {
-                        "type": "boolean",
-                        "description": "If true, overwrites the original file without creating a backup. Default is false (creates backup).",
-                    },
-                },
-                "required": ["file_path", "tags"],
-            },
-        ),
-        Tool(
-            name="remove_metadata",
-            description="Remove metadata from a file using ExifTool. Can remove all metadata or specific tags.",
+            description="Read metadata from a file using ExifTool. Supports images, videos, audio files, PDFs, and many other formats. Returns detailed metadata including EXIF, IPTC, XMP, and format-specific information. Files are read from /work.",
             inputSchema={
                 "type": "object",
                 "properties": {
                     "file_path": {
                         "type": "string",
-                        "description": "Path to the file to remove metadata from (absolute or relative path)",
+                        "description": "Path to the file under /work (absolute, or relative to /work)",
                     },
                     "tags": {
                         "type": "array",
                         "items": {"type": "string"},
-                        "description": "Optional: Specific metadata tags to remove (e.g., ['GPS*', 'Comment']). If not specified, all metadata is removed.",
-                    },
-                    "overwrite_original": {
-                        "type": "boolean",
-                        "description": "If true, overwrites the original file without creating a backup. Default is false (creates backup).",
+                        "description": "Optional: Specific metadata tags to return (e.g., ['DateTimeOriginal', 'Make', 'GPS*']). If not specified, all metadata is returned.",
                     },
                 },
                 "required": ["file_path"],
@@ -135,32 +138,22 @@
             )
         ]
 
-    if name == "read_metadata":
-        file_path = arguments.get("file_path")
-        tags = arguments.get("tags", [])
-
-        if not file_path:
-            return [TextContent(type="text", text="Error: file_path is required")]
-
-        # Validate file exists
-        path = Path(file_path).expanduser().resolve()
-        if not path.exists():
-            return [
-                TextContent(
-                    type="text",
-                    text=f"Error: File not found: {file_path}",
-                )
-            ]
+    arguments = arguments if isinstance(arguments, dict) else {}
 
-        # Build exiftool command
-        args = ["-json", "-a", "-G1"]
+    if name == "read_metadata":
+        tags = arguments.get("tags") or []
+        if not isinstance(tags, list) or len(tags) > 200 or not all(
+                isinstance(t, str) and 0 < len(t) <= 100 for t in tags):
+            return [TextContent(type="text", text="Error: tags must be a list of tag names")]
 
-        # Add specific tags if requested
-        if tags:
-            for tag in tags:
-                args.append(f"-{tag}")
+        # Validate the path: a file under /work
+        try:
+            path = _input_path(arguments.get("file_path"))
+        except ValueError as exc:
+            return [TextContent(type="text", text=f"Error: {exc}")]
 
-        args.append(str(path))
+        # Build exiftool command: fixed options, the file last (an absolute path)
+        args = ["-json", "-a", "-G1", str(path)]
 
         # Run exiftool
         stdout, stderr, returncode = await run_exiftool(args)
@@ -169,7 +162,7 @@
             return [
                 TextContent(
                     type="text",
-                    text=f"Error running exiftool: {stderr}",
+                    text=f"Error running exiftool: {stderr[:4000]}",
                 )
             ]
 
@@ -179,7 +172,10 @@
 
             # Format output nicely
             if metadata and len(metadata) > 0:
-                formatted = json.dumps(metadata[0], indent=2)
+                selected = _select(metadata[0], tags) if tags else metadata[0]
+                formatted = json.dumps(selected, indent=2)
+                if len(formatted) > MAX_OUTPUT:
+                    formatted = formatted[:MAX_OUTPUT] + "\n[... cut]"
                 return [
                     TextContent(
                         type="text",
@@ -197,130 +193,11 @@
             return [
                 TextContent(
                     type="text",
-                    text=f"Error parsing exiftool output: {e}\n\nRaw output:\n{stdout}",
-                )
-            ]
-
-    elif name == "write_metadata":
-        file_path = arguments.get("file_path")
-        tags = arguments.get("tags", {})
-        overwrite_original = arguments.get("overwrite_original", False)
-
-        if not file_path:
-            return [TextContent(type="text", text="Error: file_path is required")]
-
-        if not tags or not isinstance(tags, dict):
-            return [
-                TextContent(
-                    type="text",
-                    text="Error: tags must be a non-empty dictionary of key-value pairs",
+                    text=f"Error parsing exiftool output: {e}\n\nRaw output:\n{stdout[:4000]}",
                 )
             ]
 
-        # Validate file exists
-        path = Path(file_path).expanduser().resolve()
-        if not path.exists():
-            return [
-                TextContent(
-                    type="text",
-                    text=f"Error: File not found: {file_path}",
-                )
-            ]
-
-        # Build exiftool command
-        args = []
-
-        # Add overwrite option if requested
-        if overwrite_original:
-            args.append("-overwrite_original")
-
-        # Add tag assignments
-        for tag, value in tags.items():
-            args.append(f"-{tag}={value}")
-
-        args.append(str(path))
-
-        # Run exiftool
-        stdout, stderr, returncode = await run_exiftool(args)
-
-        if returncode != 0:
-            return [
-                TextContent(
-                    type="text",
-                    text=f"Error writing metadata: {stderr}",
-                )
-            ]
-
-        backup_msg = (
-            "" if overwrite_original else " (backup created with _original suffix)"
-        )
-        return [
-            TextContent(
-                type="text",
-                text=f"Successfully wrote metadata to {path.name}{backup_msg}\n\n{stdout}",
-            )
-        ]
-
-    elif name == "remove_metadata":
-        file_path = arguments.get("file_path")
-        tags = arguments.get("tags", [])
-        overwrite_original = arguments.get("overwrite_original", False)
-
-        if not file_path:
-            return [TextContent(type="text", text="Error: file_path is required")]
-
-        # Validate file exists
-        path = Path(file_path).expanduser().resolve()
-        if not path.exists():
-            return [
-                TextContent(
-                    type="text",
-                    text=f"Error: File not found: {file_path}",
-                )
-            ]
-
-        # Build exiftool command
-        args = []
-
-        # Add overwrite option if requested
-        if overwrite_original:
-            args.append("-overwrite_original")
-
-        # Add tag removal
-        if tags:
-            # Remove specific tags
-            for tag in tags:
-                args.append(f"-{tag}=")
-        else:
-            # Remove all metadata
-            args.append("-all=")
-
-        args.append(str(path))
-
-        # Run exiftool
-        stdout, stderr, returncode = await run_exiftool(args)
-
-        if returncode != 0:
-            return [
-                TextContent(
-                    type="text",
-                    text=f"Error removing metadata: {stderr}",
-                )
-            ]
-
-        backup_msg = (
-            "" if overwrite_original else " (backup created with _original suffix)"
-        )
-        tags_msg = f"tags: {', '.join(tags)}" if tags else "all metadata"
-        return [
-            TextContent(
-                type="text",
-                text=f"Successfully removed {tags_msg} from {path.name}{backup_msg}\n\n{stdout}",
-            )
-        ]
-
     elif name == "list_supported_formats":
-        # Run exiftool -listwf to get writable formats
         # Run exiftool -listf to get readable formats
         stdout, stderr, returncode = await run_exiftool(["-listf"])
 
```
