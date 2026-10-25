"""Tests of tests/axross-smoke.json and scripts/axross_smoke.py (standard library unittest).

tests/axross-smoke.json is the machine-readable smoke spec axross's own tests run against
every catalog entry (install, tools/list, a real call, a refused call). These tests hold it
to the catalog offline: every entry has a spec, every tool, target, mount and file a spec
names exists, and each server's recorded tool list (servers/<name>/tools.json) covers what
its specs use.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import copy
import gzip
import importlib.util
import json
import unittest
from pathlib import Path

HUB = Path(__file__).resolve().parent.parent
SPEC_PATH = HUB / "tests" / "axross-smoke.json"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = _load("axross_smoke", HUB / "scripts" / "axross_smoke.py")


def _catalog() -> dict:
    return json.loads((HUB / "catalog.json").read_text(encoding="utf-8"))


def _tools() -> dict[str, list[str]]:
    return smoke.load_tools(HUB)


def _spec() -> dict:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


class TheCommittedSpec(unittest.TestCase):
    def test_it_matches_the_catalog_and_the_recorded_tools(self):
        problems = smoke.validate(_spec(), _catalog(), _tools(), HUB)
        self.assertEqual(problems, [])

    def test_every_catalog_entry_has_exactly_one_spec(self):
        names = [s["name"] for s in _spec()["servers"]]
        self.assertEqual(sorted(names), sorted(e["name"] for e in _catalog()["entries"]))
        self.assertEqual(len(names), len(set(names)))

    def test_every_server_folder_has_a_tool_list(self):
        for folder in sorted((HUB / "servers").glob("*/server.json")):
            self.assertTrue((folder.parent / "tools.json").is_file(), folder.parent.name)

    def test_the_per_server_smoke_specs_use_only_recorded_tools(self):
        tools = _tools()
        for path in sorted((HUB / "servers").glob("*/smoke.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            used = set(data.get("expect_tools", [])) | {c["tool"] for c in data.get("calls", [])}
            self.assertLessEqual(used, set(tools[path.parent.name]), path.parent.name)

    def test_inline_files_decode_and_are_small(self):
        for server in _spec()["servers"]:
            for item in server.get("files", []):
                data = smoke.file_bytes(item)
                self.assertGreater(len(data), 0, (server["name"], item["path"]))
                self.assertLess(len(item["base64"]), 64 * 1024, (server["name"], item["path"]))

    def test_the_target_source_is_the_committed_file(self):
        for name, target in _spec()["targets"].items():
            for item in target["files"]:
                committed = (HUB / target["source"]).read_bytes()
                self.assertEqual(smoke.file_bytes(item), committed, name)

    def test_live_network_specs_reach_only_allowlisted_services(self):
        for server in _spec()["servers"]:
            if server.get("live_needs_network"):
                self.assertIsInstance(server["network"], dict, server["name"])


class BrokenSpecsAreRefused(unittest.TestCase):
    """Each mutation of the committed spec must produce a problem that names it."""

    def setUp(self):
        self.spec = _spec()
        self.catalog = _catalog()
        self.tools = _tools()

    def problems(self, spec=None, catalog=None, tools=None) -> list[str]:
        return smoke.validate(spec or self.spec, catalog or self.catalog,
                              tools or self.tools, HUB)

    def server(self, name: str) -> dict:
        return next(s for s in self.spec["servers"] if s["name"] == name)

    def assertProblem(self, needle: str, problems: list[str]) -> None:
        self.assertTrue(any(needle in p for p in problems), f"{needle!r} not in {problems}")

    def test_a_catalog_entry_without_a_spec(self):
        self.spec["servers"] = [s for s in self.spec["servers"] if s["name"] != "yara"]
        self.assertProblem("yara: catalog entry has no smoke spec", self.problems())

    def test_a_spec_for_a_server_that_is_not_in_the_catalog(self):
        ghost = copy.deepcopy(self.server("yara"))
        ghost["name"] = "ghost"
        self.spec["servers"].append(ghost)
        self.assertProblem("ghost: no catalog entry", self.problems())

    def test_two_specs_for_one_server(self):
        self.spec["servers"].append(copy.deepcopy(self.server("capa")))
        self.assertProblem("capa: more than one smoke spec", self.problems())

    def test_an_unknown_required_tool(self):
        self.server("radare2")["tools_required"].append("no_such_tool")
        self.assertProblem("radare2: tools_required: no_such_tool is not a tool", self.problems())

    def test_an_unknown_tool_in_the_call(self):
        self.server("nmap")["call"]["tool"] = "os_detection"
        self.assertProblem("nmap: call: os_detection is not a tool", self.problems())

    def test_an_unknown_tool_in_the_refused_call(self):
        self.server("john")["refused"]["tool"] = "crack_everything"
        self.assertProblem("john: refused: crack_everything is not a tool", self.problems())

    def test_an_unknown_tool_in_a_setup_call(self):
        self.server("radare2")["setup"][0]["tool"] = "open"
        self.assertProblem("radare2: setup 1: open is not a tool", self.problems())

    def test_an_unknown_target(self):
        self.server("sqlmap")["target"] = "nowhere"
        self.assertProblem("sqlmap: target nowhere does not exist", self.problems())

    def test_target_variables_without_a_target(self):
        del self.server("nuclei")["target"]
        self.assertProblem("nuclei: uses ${TARGET_HOST}/${TARGET_PORT} but names no target",
                           self.problems())

    def test_a_file_at_a_folder_the_entry_does_not_mount(self):
        self.server("exiftool")["files"][0]["target"] = "/rules"
        self.assertProblem("exiftool: file photo.png: /rules is not a mount target",
                           self.problems())

    def test_a_required_mount_without_files(self):
        self.server("capa")["files"] = []
        self.assertProblem("capa: required mount /work gets no files", self.problems())

    def test_a_call_naming_a_file_that_the_spec_does_not_create(self):
        self.server("binwalk")["call"]["args"]["filepath"] = "/work/missing.bin"
        self.assertProblem("binwalk: call: /work/missing.bin is not one of the spec's files",
                           self.problems())

    def test_a_file_path_with_a_folder(self):
        self.server("floss")["files"][0]["path"] = "../stack.exe"
        self.assertProblem("floss: file ../stack.exe: path must be a plain file name",
                           self.problems())

    def test_broken_base64(self):
        self.server("tshark")["files"][0]["base64"] = "not base64!"
        self.assertProblem("tshark: file web.pcap: base64", self.problems())

    def test_an_empty_expected_text(self):
        self.server("gitleaks")["call"]["expect_substring"] = ""
        self.assertProblem("gitleaks: call: expect_substring", self.problems())

    def test_full_network_for_an_entry_without_it(self):
        self.server("tshark")["network"] = "full"
        self.assertProblem("tshark: network full but the catalog entry has network none",
                           self.problems())

    def test_an_allowlist_host_the_catalog_does_not_allow(self):
        self.server("crtsh")["network"] = {"allowlist": ["crt.sh:443", "example.org:443"]}
        self.assertProblem("crtsh: allowlist host example.org:443 is not in the catalog entry",
                           self.problems())

    def test_a_tool_that_left_the_recorded_list(self):
        tools = copy.deepcopy(self.tools)
        tools["sleuthkit"].remove("read_file")
        self.assertProblem("sleuthkit: call: read_file is not a tool", self.problems(tools=tools))

    def test_a_server_without_a_recorded_tool_list(self):
        tools = copy.deepcopy(self.tools)
        del tools["ffuf"]
        self.assertProblem("ffuf: no servers/ffuf/tools.json", self.problems(tools=tools))

    def test_a_target_without_a_pinned_digest(self):
        self.spec["targets"]["web"]["digest"] = "latest"
        self.assertProblem("target web: digest", self.problems())

    def test_a_timeout_out_of_range(self):
        self.server("dnstwist")["timeout_s"] = 0
        self.assertProblem("dnstwist: timeout_s", self.problems())

    def test_a_live_network_spec_on_a_full_network(self):
        self.server("ffuf")["live_needs_network"] = True
        self.assertProblem("ffuf: live_needs_network", self.problems())


class FileHelpers(unittest.TestCase):
    def test_plain_and_gzip_base64(self):
        raw = b"MCPHUB" * 100
        plain = {"target": "/work", "path": "a", "base64": base64.b64encode(raw).decode()}
        packed = {"target": "/work", "path": "a", "gzip": True,
                  "base64": base64.b64encode(gzip.compress(raw, mtime=0)).decode()}
        self.assertEqual(smoke.file_bytes(plain), raw)
        self.assertEqual(smoke.file_bytes(packed), raw)

    def test_gzip_flag_on_data_that_is_not_gzip(self):
        item = {"target": "/work", "path": "a", "gzip": True,
                "base64": base64.b64encode(b"plain").decode()}
        with self.assertRaises(ValueError):
            smoke.file_bytes(item)


if __name__ == "__main__":
    unittest.main()


class RunLineEngineTest(unittest.TestCase):
    """axross runs podman, whose tmpfs would copy the image's /tmp up unless
    told not to (notmpcopyup); CI smoke-tests with docker, which refuses that
    option and never copies up."""

    def _tmpfs(self, program):
        st = _load("smoke_test", HUB / "scripts" / "smoke_test.py")
        argv = st.run_command("x", "ghcr.io/c0decave/axross-mcp-x@sha256:" + "0" * 64,
                              program=program)
        return next(a for a in argv if a.startswith("--tmpfs=/tmp:"))

    def test_podman_gets_notmpcopyup(self):
        self.assertIn("notmpcopyup", self._tmpfs("podman").split(","))

    def test_docker_gets_no_notmpcopyup(self):
        flag = self._tmpfs("docker")
        self.assertNotIn("notmpcopyup", flag)
        self.assertIn("noexec", flag)  # the rest of the tmpfs stays as it is

    def test_a_docker_path_counts_as_docker(self):
        self.assertNotIn("notmpcopyup", self._tmpfs("/usr/bin/docker"))
