# radare2 - provenance and audit

| | |
|---|---|
| MCP server | r2mcp, the official radare2 MCP server: https://github.com/radareorg/radare2-mcp |
| Commit | `562c0cf23c42b65b3052f0b294d8778c20facbde` (tag 1.9.0, 2026-10-15) |
| Server licence | MIT, Copyright (c) 2024 dnakov (`LICENSES/r2mcp-LICENSE`) |
| Tool | radare2 6.2.4, https://github.com/radareorg/radare2 at `485e5e205b190fc297a2a95a6f982ff5d9f54039` (tag 6.2.4); its meson subprojects (sdb 2.5.8, capstone, quickjs, otezip 0.4.8, zydis 4.1.0) at the revisions pinned in its `subprojects/*.wrap` |
| Tool licence | LGPL-3.0-only for most of radare2; some plugins and dependencies are GPL-3.0, Apache-2.0, BSD, MIT, Zlib (`LICENSES/radare2/`, from radare2's `COPYING.md`, `doc/licenses.md` and `doc/licenses/`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |
| Local patches | none |

Both are built from source; the Dockerfile fetches exactly these commits (`git fetch` of the
commit ID, and the build stops unless `git rev-parse HEAD` equals it).

## Audit

**Tools (32):** `open_file`, `close_file`, `analyze`, `list_functions`, `list_functions_tree`,
`list_libraries`, `list_imports`, `list_exports`, `list_sections`, `list_memory_maps`,
`show_function_details`, `get_current_address`, `show_info`, `list_symbols`,
`list_entrypoints`, `list_methods`, `list_classes`, `list_decompilers`, `rename_function`,
`rename_flag`, `use_decompiler`, `get_function_prototype`, `set_function_prototype`,
`set_comment`, `list_strings`, `list_all_strings`, `xrefs_to`, `decompile_function`,
`list_files`, `disassemble_function`, `disassemble`, `calculate`, `sql` (needs the r2xsql
plugin, not included). The renaming and comment tools change radare2's in-memory analysis
only; the file is opened read-only.

**Command execution:** r2mcp is C and calls radare2's API in-process. Tool arguments go into
radare2 commands built with a leading `'` (radare2's "no special characters" mode), so a
name or address cannot chain further commands (`;`, `|`, `!`, backticks). The raw
`run_command`, `run_javascript` and `run_script` tools exist only with `-r` - not used here.
`curl` is executed only in supervisor mode (`-S`) - not used here, and curl is not installed.

**Sandboxes used (entrypoint `r2mcp -s /work -g none`):**

- `-s /work`: `open_file` accepts only paths under `/work`. Checked: `open_file /etc/passwd`
  fails with `-s /work` and succeeds with `-s /` (negative control);
- `-g none`: radare2's own sandbox (`cfg.sandbox`) with no permissions - no program
  execution, sockets, network or disk writes from radare2 commands. r2mcp's default for
  stdio would allow exec and sockets.

**Network:** none. **Files:** reads binaries from `/work`; writes nothing.
