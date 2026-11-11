# radare2 - provenance and audit

| | |
|---|---|
| MCP server | r2mcp, the official radare2 MCP server: https://github.com/radareorg/radare2-mcp |
| Commit | `562c0cf23c42b65b3052f0b294d8778c20facbde` (tag 1.9.0, 2026-10-15) |
| Server licence | MIT, Copyright (c) 2024 dnakov (`LICENSES/r2mcp-LICENSE`) |
| Tool | radare2 6.2.4, https://github.com/radareorg/radare2 at `485e5e205b190fc297a2a95a6f982ff5d9f54039` (tag 6.2.4); its meson subprojects (sdb 2.5.8, capstone, quickjs, otezip 0.4.8, zydis 4.1.0) at the revisions pinned in its `subprojects/*.wrap` |
| Tool licence | LGPL-3.0-only for most of radare2; some plugins and dependencies are GPL-3.0, Apache-2.0, BSD, MIT, Zlib (`LICENSES/radare2/`, from radare2's `COPYING.md`, `doc/licenses.md` and `doc/licenses/`) |
| Base image | `docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |
| Local patches | `patches/0001-open-file-refuses-uris-commands-stay-one-line.patch` (r2mcp; see Review) |

Both are built from source; the Dockerfile fetches exactly these commits (`git fetch` of the
commit ID, and the build stops unless `git rev-parse HEAD` equals it), applies the patch to r2mcp
and checks the patched file's SHA-256.

## Audit

**Tools (32, exactly `tools.json`; the entrypoint enables only these with `-e`):** `open_file`,
`close_file`, `analyze`, `list_functions`, `list_functions_tree`, `list_libraries`,
`list_imports`, `list_exports`, `list_sections`, `list_memory_maps`, `show_function_details`,
`get_current_address`, `show_info`, `list_symbols`, `list_entrypoints`, `list_methods`,
`list_classes`, `list_decompilers`, `rename_function`, `rename_flag`, `use_decompiler`,
`get_function_prototype`, `set_function_prototype`, `set_comment`, `list_strings`,
`list_all_strings`, `xrefs_to`, `decompile_function`, `list_files`, `disassemble_function`,
`disassemble`, `calculate`. Not offered (r2mcp would accept them without `-e`): `sql` (needs the
r2xsql plugin), `search`, `hexdump`, `lookup_address`, `lookup_export`, `lookup_symbol` and the
debugger tools `get_pid`, `list_threads`, `dump_registers`, `memory_map_here`,
`list_heap_allocations`. The renaming and comment tools change radare2's in-memory analysis
only; the file is opened read-only. No MCP prompts (`-N`).

**Command execution:** r2mcp is C and calls radare2's API in-process. Tool arguments go into
radare2 commands built with a leading `'` (radare2's "no special characters" mode), so a
name or address cannot chain further commands (`;`, `|`, `!`, backticks); patch 0001 also cuts
every such command at a newline (Review, finding 3). `open_file` takes no URI (patch 0001,
finding 1: upstream let `r2pipe://` run a shell command and `nocache://` read any file). The raw
`run_command`, `run_javascript` and `run_script` tools exist only with `-r` - not used here.
`curl` is executed only in supervisor mode (`-S`) - not used here, and curl is not installed.

**Sandboxes used (entrypoint `r2mcp -s /work -g none -N -e ...`):**

- `-s /work`: `open_file` accepts only paths under `/work`, and (patch 0001) no URI. Checked:
  `open_file /etc/passwd` fails with `-s /work` and succeeds with `-s /` (negative control); the
  smoke spec also requires `open_file nocache:///etc/passwd` to fail;
- `-g none`: radare2's own sandbox (`cfg.sandbox`) with no permissions - no program
  execution, sockets, network or disk writes from radare2 commands (r2mcp lifts it only while it
  opens or closes the file, Review finding 5). r2mcp's default for stdio would allow exec and
  sockets.

**Network:** none. **Files:** reads binaries from `/work`; writes nothing.

## Review

Reviewed for this repository on 2026-11-11, at exactly the pinned commit `562c0cf2` (fetched by
commit ID into an empty folder, `git fsck` clean; never built or run on the review machine): every
file of r2mcp that is built, line by line, for backdoors, hidden network access, telemetry, command
or shell execution, path traversal out of `/work`, unsafe parsing, memory-safety bugs reachable from
tool arguments (buffers, format strings, command strings) and anything a malicious binary or a
malicious MCP client could use to get past the documented limits. Where r2mcp's safety depends on
radare2's behaviour, radare2 6.2.4's code at `485e5e20` was read for exactly that (not reviewed as a
whole: radare2 is the tool): the command dispatcher and its `'` mode (`libr/core/cmd.c`,
`cmd_api.c`), the sandbox (`libr/util/sandbox.c`, `cconfig.c`'s `cfg.sandbox*`), the io plugins'
URI checks (`libr/io/p/*.c`, `libr/meson.build`), `r2pipe_open` (`libr/socket/r2pipe.c`), the
handlers of every command r2mcp builds from an argument (`cmd_meta.inc.c` `CC`, `cmd_anal.inc.c`
`afs`/`afn`, `cmd_flag.inc.c` `fr`, `cmd_info.inc.c` `ic`, `cmd.c` `ls`) and `r_num_math`'s core
callback (`numvars.inc.c`).

**What ships.** The image installs only the `r2mcp` program, compiled from `src/main.c` and
`src/r2mcp.c` (which includes `path.inc.c`, `utils.inc.c`, `bind.inc.c`, `r2api.inc.c` and through
it `curl.inc.c`), `readbuffer.c`, `tools.c` (includes `path.inc.c`, `utils.inc.c`), `dsltest.c`,
`prompts.c`, `jsonrpc.c`, `validation.c`, `sessions.c` and the headers. `make` also compiles
`src/plugin.c` (the radare2 core plugin `libcore_r2mcp.so`) and `svc/r2mcp-svc.c` (the supervisor);
neither is installed, both were read too. All 24 files of `src/` (6,202 lines), `svc/` (286) and the
build files (561) were read in full:

| File | Lines | SHA-256 (upstream) |
|---|---:|---|
| `src/main.c` | 520 | `bbb4baa9246ee4dc0eba5a36f4acfced6a1f95313c437e4b621346e4708dc54d` |
| `src/r2mcp.c` | 877 | `5334297a050a30e470a54e448cf94ab76f4213e7024f116bc4edeb029fdb9bfc` |
| `src/tools.c` | 1,634 | `990679c3de56d0bd85e5807f72e7064524392ff724d762d2372a8d782bafd906` |
| `src/r2api.inc.c` | 291 | `06378dca6da5a1377d69aaee7a1d08376df328615900c6cc6104c56f2ed0b284` (patched: below) |
| `src/utils.inc.c` | 258 | `4b05c96ae9f620386fcd775e466fe8d244c2661975db30f6377fa8b4762ecd84` |
| `src/path.inc.c` | 115 | `454218b59acff2d471529863b708d3205883dd0cf475be62daaf0753da62efc8` |
| `src/bind.inc.c` | 48 | `49a2889350f4cdee062eb59c39c96d06da1b68cf7f5706cfdb12af3b266d5f48` |
| `src/curl.inc.c` | 240 | `7641e2ed8a2f75ef2c1fd77205efcd9d0d9c1c4361e408509ff03e888a41ad2a` |
| `src/readbuffer.c` | 119 | `3e13f6bbaf56aa3a54ceccae80b8222278e383db652b14fb46a1fa8fbde11a5b` |
| `src/jsonrpc.c` | 211 | `12c2580a0559e873a868becf137e6d67ca72943131091441ff1965df9813ceff` |
| `src/validation.c` | 176 | `3de6f8a5397b2853e3bb166fa96946cdee8737c67cf4482aa874d0f9557178a6` |
| `src/prompts.c` | 408 | `298e1654fd6284f54ceccc85516d6638ef2890e9d1945f827a1406da118bbf30` |
| `src/sessions.c` | 103 | `ebdfe3432d14c7dfae1ce9b7c0c6bf126afeaf81657012009ff7748802769f6e` |
| `src/dsltest.c` | 177 | `afdbd06daca3cefe6e1e7db3747ee8e2363241b50a7c548ad4ed301c15e97bab` |
| `src/plugin.c` (built, not shipped) | 540 | `116cdae4b51cff9ff7c0adbb942386a27544b69fd7ae0ea3bfbd7b43870dd64d` |
| `src/r2mcp.h` | 184 | `ceaa495ab18855f3566177b865566d86ee1b801026422e1722f822ca07a72514` |
| `src/tools.h` | 47 | `cd585c46e3c94b10b91797e04c913effd953525c5c7a126f37bceb2eb40e7ffc` |
| `src/prompts.h` | 30 | `b1d992a42ce163b1bf1f8de732bb07b4b1e5254884df28d67a141e02e06c198c` |
| `src/sessions.h` | 32 | `2c6cb39b95e75f3202f46df0a9f8ff63756ffaa031fba08c883d023e203a3a01` |
| `src/jsonrpc.h` | 19 | `992586c2e089f65744eae71f9d92b1c82e7f0020a0c43af5669efed28cefe98c` |
| `src/readbuffer.h` | 19 | `4dfd312ee8209048959b3684f669b87f56dbd7800043439291e6de441e3ad62e` |
| `src/validation.h` | 18 | `38278509e5967e38bc5ec03ea663a6b21f85cef9a25371b8135a50ab3df433de` |
| `src/config.h.acr` | 7 | `94e6e7a7a870a8428ef7a7bd58914814a5d6d76e8094bc64f7cecdf5b9445422` |
| `src/Makefile` | 129 | `d7f2a3329c21940a29ece3311f18eb803c972c4ef1f836c4b7d502729f4d9ebf` |
| `svc/r2mcp-svc.c` (built, not shipped) | 248 | `0519e447a33874f4e287bcf5ddbaf7fd2f1bb60fd9be34af1523dbce39044fe8` |
| `svc/Makefile` | 38 | `e0c86f87daad0f965e5e0bf09a69689f84aea00c5d566f91a6cb2abcff82293f` |
| `Makefile` | 36 | `4c4487deda4f86461129f5b73c8b27397ba9ca2fc7a537122ea73614a0425fc5` |
| `configure` (ACR 2.2.8, run by the build) | 506 | `80f48d54e8acf6be8e6c24b43bd82897c5e1f95859312d65cdaa3ff01ae4869e` |
| `configure.acr` | 19 | `0704f479492b1c46338a947832f25ecf1c50c4c57dc6cd8f92c6d971f802c905` |

The build runs only `configure` (it writes `src/config.h` from `config.h.acr`, nothing is fetched)
and `make` (`src/` and `svc/`); `make install`, `user-install`, the Debian, WASM and Codex-plugin
scripts under `dist/` and the test scripts are not used.

**No backdoor, no telemetry, no hidden network access found.** r2mcp opens a socket only as an HTTP
server (`-H`, `r2mcp.c:766`), starts processes only for the HTTP r2pipe client and the supervisor
(`-u`/`-S`: `curl` by `execvp` without a shell, `curl.inc.c:141-226`) and for `-L`'s `r2agent -Lj`
(`tools.c:1171`); this image uses none of these flags and has no curl. Nothing is sent anywhere,
no update check, no hard-coded host but `localhost` defaults for those modes. Every printf-like
call has a literal format (argument strings go in as `%s`), no fixed-size buffer is filled from an
argument (`id_buf[32]`, cursor buffers: `%d`/`%lld` only), the stdin framing (`readbuffer.c`)
copies with bounds; JSON output is built with radare2's `pj_*` (escaped).

**Findings, and what this image does about them:**

1. **`open_file` took any URI past `-s`, with radare2's sandbox switched off (high).**
   `r2_open_file` checks the path against `-s` only when it contains no `://`
   (`r2api.inc.c:155-163`) and turns radare2's sandbox off for every open (`r2api.inc.c:179-183`,
   `r_sandbox_disable (true)`, `cfg.sandbox=false`). So one tool argument reached every io plugin
   compiled into radare2: `r2pipe://CMD` forks and runs `CMD` with `/bin/sh -c`
   (`libr/socket/r2pipe.c` `r2pipe_open` -> `r_sandbox_system`, allowed because the sandbox is off),
   `dbg://PROGRAM` starts a program under ptrace, `nocache:///etc/passwd`, `gzip://`, `zip://`,
   `self://`, `procpid://` read files and memory outside `/work`, `http://`, `gdb://`, `rap://`
   would open sockets. A malicious or prompt-injected MCP client could run any program of the image;
   the earlier checks (`open_file /etc/passwd` refused) never tried a URI. Under the hardened run
   line that stays inside the container (no network, `/work` read-only, read-only root, no
   capabilities), but "nothing is executed" and "only `/work`" were not true. **Patch 0001:** with
   `-s` a path containing `://` is refused before anything is opened. Every radare2 6.2.4 io plugin
   other than the plain-file one is selected by a `scheme://` prefix (checked: the `check`
   functions of all of `libr/io/p/`), so what remains is a plain absolute path that `-s` resolves
   (symlinks included, `path.inc.c:72-99`) and requires under `/work`, hidden files and `..`
   refused. The smoke spec now also calls `open_file nocache:///etc/passwd` and requires the
   refusal.
2. **More tools than listed (medium).** `tools/list` returns 32 tools per page (`r2mcp.c:493`) and
   the smoke runners read one page, but `tools_call` accepts every tool of the mode
   (`tools.c:1419-1425`): `calculate` (page 2) and `get_pid`, `list_threads`, `dump_registers`,
   `hexdump`, `memory_map_here`, `list_heap_allocations`, `search` (its query goes raw into `'/`),
   `lookup_address`, `lookup_export`, `lookup_symbol` were callable without being listed or audited;
   `sql` hands its raw query to every loaded radare2 core plugin (`tools.c:1084-1089`) and does
   nothing without r2xsql. **Flags:** `-e` for exactly the 32 tools of `tools.json` (`sql` out,
   `calculate` in): one page, and r2mcp refuses every other tool on call too (`tool_available` ->
   `tool_eligible`, `tools.c:280-291`; `-p` is not given).
3. **Command strings and the `'` mode (low; no chaining found).** Every tool that puts a string
   into a radare2 command prefixes it with `'`: `list_methods` (`'ic NAME`, `tools.c:632`),
   `set_comment` (`'@0x..'CC TEXT`, `tools.c:713`), `set_function_prototype` (`'@0x..'afs PROTO`,
   `tools.c:724`), `rename_flag` (`'@0x..'fr OLD NEW`, `tools.c:868`), `rename_function`
   (`'@0x..'afn NAME`, `tools.c:883`), `list_files` (`'ls -q PATH`, `tools.c:615`, the path also
   checked by `-s`); addresses are parsed to numbers first and printed with `0x%llx`
   (`validation.c:62-80`), counts with `%d`, and `use_decompiler` only takes a name radare2 itself
   lists (`tools.c:817-842`). radare2 hands a `'` line to the command's handler as one call, without
   looking at `;`, `|`, `>`, `@`, `@@`, `~`, backticks, `$()` or newlines (`handle_command_call`,
   `cmd.c:3756`) - but when that call returns -1 (unknown or aborted), `core_cmd_context` falls back
   to the normal parser (`cmd.c:6814`), which splits at newlines and runs every further line as a
   full command (`run_cmd_context`, `cmd.c:6707`). The six handlers (`cmd_meta`, `cmd_anal`,
   `cmd_flag`, `cmd_info`, `cmd_l`) never return -1 and none passes its argument to the command
   parser again (`ls` would, as `md %s`, only on a radare2 mount; none can be made), so no argument
   could chain a command - but only because of radare2 internals, and `r2_cmd_filter`
   (`r2api.inc.c:80-102`) cut at `|`, `>`, `` ` ``, `$(` and a leading `!`, not at newlines.
   **Patch 0001** also cuts every command r2mcp builds at `\n` and `\r`: none can have a second line.
4. **Prompts from the analysed folder (low).** Without `-N`, r2mcp loads `*.r2ai.md` from
   `./prompts` (`prompts.c:291`) - the working directory is `/work` - and serves them as MCP prompts:
   a sample folder could ship text for the model. **Flag `-N`:** no prompts.
5. **radare2's sandbox is off while a file is opened or closed (informational).** `open_file` and
   `close_file` (`r2api.inc.c:179-183`, `tools.c:472-481`) must: with grain `none` radare2 cannot
   open a file at all (`r_sandbox_open` needs the disk grain). The binary's headers are parsed by
   radare2's bin plugins in that window; nothing there runs a command built from the file, and the
   container is the boundary for radare2's parsers (the tool, not reviewed here). Before the first
   `open_file` the sandbox is not on yet, but r2mcp runs no command before a file is open
   (`r2mcp.c:268`), and `calculate` only evaluates a number.
6. **Numbers and expressions (informational).** Addresses and `calculate` go through radare2's
   `r_num_math` with the core's callback: flags, `${config}` reads and `$k{...}` queries of radare2's
   in-memory sdb, no command (`numvars.inc.c:793-`). `set_function_prototype` hands its text to
   radare2's C type parser (radare2's code).
7. **Denial of service only (informational).** A message without its closing brace grows the stdin
   buffer without bound (`readbuffer.c:262-278`); a huge `cursor`/`start` overflows a signed `int`
   (`utils.inc.c:56`, `tools.c:349`, `tools.c:593`) and yields an empty page, no memory access;
   `analyze` level 4 on a large file takes long. All bounded by the container's memory and pid
   limits.
8. **Not used here (informational).** HTTP mode and its bearer token, sessions (`-X`, `-L`), the
   `-r` tools, `-c` startup commands, `plugin.c`, `svc/`; `dsltest.c` runs only with `-T`. The
   descriptions of `open_file` and `decompile_function` carry `<think>` hints for the model
   (harmless steering, shown in `tools/list`).

### The patch (`patches/`, applied with `patch -p1 --fuzz=0`; the build then checks the result)

| Patch | SHA-256 | What |
|---|---|---|
| `0001-open-file-refuses-uris-commands-stay-one-line.patch` | `1e5304824804205b6d321e8ae83ab515a1408fdbb1f350ec01a850295cd35e85` | `src/r2api.inc.c`: `r2_open_file` refuses a path containing `://` when `-s` is set (finding 1); `r2_cmd_filter` also cuts at `\n` and `\r` (finding 3) |

The patched `src/r2api.inc.c` must have SHA-256
`a96fcc518cfddd4f612587bd9fc45d1b58b2519ca9be3f6477dbca1102f0b120` or the build stops. The patch was
applied to the pinned commit here (`git apply --check`, then the hash above); it is compiled and run
only in CI, which builds the image and runs the smoke spec (the reviewed code is never executed on
the review machine). The entrypoint flags `-N` and `-e` (findings 2 and 4) need no patch.

**Verdict:** reviewed completely; with patch 0001 and the flags above nothing found remains open.
Signed once a CI run has built this Dockerfile and its smoke runs passed for that digest.
