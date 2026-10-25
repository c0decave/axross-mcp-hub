"""Tests of scripts/make_catalog.py (standard library unittest).

    python3 -m unittest discover -s tests -v
    AXROSS_DIR=/path/to/axross /path/to/axross/.venv/bin/python -m unittest discover -s tests

With AXROSS_DIR the catalogs are also read by axross's own validator.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

HUB = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("make_catalog", HUB / "scripts" / "make_catalog.py")
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "ab" * 32


class Hub:
    """A copy of the hub's servers/ in a temporary folder, with a digests.json
    that has no image published yet."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copytree(HUB / "servers", self.root / "servers",
                        ignore=shutil.ignore_patterns("src", "LICENSES", "*.txt", "*.in"))
        self.names = sorted(p.parent.name for p in (self.root / "servers").glob("*/server.json"))
        # Every test starts unpublished, whatever the hub's own digests.json
        # holds by now (it held only nulls when these tests were written).
        digests = json.loads((HUB / "digests.json").read_text())
        digests["images"] = {name: None for name in self.names}
        (self.root / "digests.json").write_text(json.dumps(digests, indent=2) + "\n")

    def run(self, *args: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = mc.main(["--root", str(self.root), *args])
        return code, out.getvalue() + err.getvalue()

    def ci_file(self, name: str, digest: str, image: str | None = None) -> Path:
        folder = self.root / "ci"
        folder.mkdir(exist_ok=True)
        path = folder / f"digest-{name}.json"
        path.write_text(json.dumps({"name": name, "image": image or mc.IMAGE_PREFIX + name,
                                    "digest": digest}))
        return path

    def server(self, name: str) -> dict:
        return json.loads((self.root / "servers" / name / "server.json").read_text())

    def set_server(self, name: str, data: dict) -> None:
        (self.root / "servers" / name / "server.json").write_text(json.dumps(data))

    def catalog(self) -> dict:
        return json.loads((self.root / "catalog.json").read_text())

    def close(self) -> None:
        self.tmp.cleanup()


class MakeCatalogTest(unittest.TestCase):
    def setUp(self) -> None:
        self.hub = Hub()
        self.addCleanup(self.hub.close)

    # -- happy path --------------------------------------------------------------------

    def test_all_digests_give_a_pinned_catalog(self):
        for name in self.hub.names:
            self.hub.ci_file(name, D1)
        code, text = self.hub.run("--ci-digests", str(self.hub.root / "ci"), "--write-digests")
        self.assertEqual(code, 0, text)
        catalog = self.hub.catalog()
        self.assertEqual(catalog["state"], "pinned")
        self.assertNotIn("pending", catalog)
        self.assertEqual([e["name"] for e in catalog["entries"]], self.hub.names)
        for entry in catalog["entries"]:
            self.assertEqual(entry["digest"], D1)
            self.assertEqual(entry["image"], mc.IMAGE_PREFIX + entry["name"])
            self.assertEqual(list(entry), [k for k in mc.ENTRY_KEYS if k in entry])
        self.assertEqual(json.loads((self.hub.root / "digests.json").read_text())["images"],
                         {n: D1 for n in self.hub.names})
        code, text = self.hub.run("--check")
        self.assertEqual(code, 0, text)

    def test_the_committed_catalog_is_current(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = mc.main(["--root", str(HUB), "--check", "--allow-pending"])
        self.assertEqual(code, 0, out.getvalue())

    def test_writing_twice_gives_the_same_bytes(self):
        self.hub.run()
        first = (self.hub.root / "catalog.json").read_bytes()
        self.hub.run()
        self.assertEqual(first, (self.hub.root / "catalog.json").read_bytes())

    # -- sad path ----------------------------------------------------------------------

    def test_missing_digests_are_pending_and_fail_the_check(self):
        self.hub.ci_file(self.hub.names[0], D2)
        code, text = self.hub.run("--ci-digests", str(self.hub.root / "ci"))
        self.assertEqual(code, 0, text)
        catalog = self.hub.catalog()
        self.assertEqual(catalog["state"], "pending-digests")
        self.assertEqual(catalog["pending"], self.hub.names[1:])
        self.assertIn("PENDING", catalog["description"])
        pinned = [e for e in catalog["entries"] if "digest" in e]
        self.assertEqual([e["name"] for e in pinned], self.hub.names[:1])
        code, text = self.hub.run("--check")
        self.assertEqual(code, 1)
        self.assertIn("digests pending", text)

    def test_a_stale_catalog_fails_the_check(self):
        self.hub.run()
        data = self.hub.server("nmap")
        data["title"] = "Nmap (changed)"
        self.hub.set_server("nmap", data)
        code, text = self.hub.run("--check", "--allow-pending")
        self.assertEqual(code, 1)
        self.assertIn("not what servers", text)

    def test_a_malformed_digest_in_digests_json_is_refused(self):
        path = self.hub.root / "digests.json"
        data = json.loads(path.read_text())
        data["images"]["nmap"] = "sha256:1234"
        path.write_text(json.dumps(data))
        code, text = self.hub.run()
        self.assertEqual(code, 1)
        self.assertIn("is not sha256", text)
        self.assertFalse((self.hub.root / "catalog.json").exists())

    def test_a_ci_digest_for_another_image_is_refused(self):
        self.hub.ci_file("nmap", D1, image="ghcr.io/someone/else")
        code, text = self.hub.run("--ci-digests", str(self.hub.root / "ci"))
        self.assertEqual(code, 1)
        self.assertIn("is not ghcr.io/c0decave/axross-mcp-nmap", text)

    def test_a_digest_inside_server_json_is_refused(self):
        data = self.hub.server("yara")
        data["digest"] = D1
        self.hub.set_server("yara", data)
        code, text = self.hub.run()
        self.assertEqual(code, 1)
        self.assertIn("belongs in digests.json", text)

    def test_unknown_keys_and_bad_mounts_are_refused(self):
        data = self.hub.server("yara")
        self.hub.set_server("yara", {**data, "command": ["sh"]})
        self.assertIn("unknown keys command", self.hub.run()[1])
        self.hub.set_server("yara", {**data, "mounts": [{"target": "/work/../etc"}]})
        self.assertIn("is not an absolute path", self.hub.run()[1])
        self.hub.set_server("yara", {**data, "mounts": [{"target": "work"}]})
        self.assertEqual(self.hub.run()[0], 1)

    # -- edge cases --------------------------------------------------------------------

    def test_upper_case_and_short_digests_are_refused(self):
        for bad in ("sha256:" + "A" * 64, "sha256:" + "1" * 63, "sha512:" + "1" * 64, ""):
            with self.subTest(bad=bad):
                self.hub.ci_file("capa", bad)
                code, text = self.hub.run("--ci-digests", str(self.hub.root / "ci"))
                self.assertEqual(code, 1)

    def test_digests_of_unknown_servers_are_refused(self):
        path = self.hub.root / "digests.json"
        data = json.loads(path.read_text())
        data["images"]["ghidra"] = D1
        path.write_text(json.dumps(data))
        code, text = self.hub.run()
        self.assertEqual(code, 1)
        self.assertIn("do not exist: ghidra", text)

    def test_a_name_that_differs_from_its_folder_is_refused(self):
        data = self.hub.server("capa")
        self.hub.set_server("capa", {**data, "name": "capa2", "image": mc.IMAGE_PREFIX + "capa2"})
        self.assertIn("differs from its folder", self.hub.run()[1])

    def test_allowlist_without_hosts_is_refused(self):
        data = self.hub.server("dnstwist")
        self.hub.set_server("dnstwist", {**data, "network": "allowlist"})
        self.assertIn("allowlist needs hosts", self.hub.run()[1])

    def test_an_empty_ci_folder_is_refused(self):
        (self.hub.root / "ci").mkdir()
        code, text = self.hub.run("--ci-digests", str(self.hub.root / "ci"))
        self.assertEqual(code, 1)
        self.assertIn("no digest-*.json", text)

    def test_two_different_digests_for_one_server_are_refused(self):
        self.hub.ci_file("nmap", D1)
        other = self.hub.root / "ci2"
        other.mkdir()
        (other / "digest-nmap.json").write_text(json.dumps(
            {"name": "nmap", "image": mc.IMAGE_PREFIX + "nmap", "digest": D2}))
        code, text = self.hub.run("--ci-digests", str(self.hub.root / "ci"), str(other))
        self.assertEqual(code, 1)
        self.assertIn("two different digests", text)


@unittest.skipUnless(os.environ.get("AXROSS_DIR"), "AXROSS_DIR (an axross checkout) not set")
class AxrossValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.hub = Hub()
        self.addCleanup(self.hub.close)
        self.axross = os.environ["AXROSS_DIR"]

    def test_a_pinned_catalog_is_accepted_by_axross(self):
        for name in self.hub.names:
            self.hub.ci_file(name, D2)
        self.assertEqual(self.hub.run("--ci-digests", str(self.hub.root / "ci"),
                                      "--write-digests")[0], 0)
        code, text = self.hub.run("--check", "--axross", self.axross)
        self.assertEqual(code, 0, text)
        self.assertIn(f"{len(self.hub.names)} entries accepted, 0 refused", text)

    def test_pending_entries_are_refused_by_axross(self):
        self.hub.ci_file("radare2", D1)
        self.assertEqual(self.hub.run("--ci-digests", str(self.hub.root / "ci"),
                                      "--write-digests")[0], 0)
        code, text = self.hub.run("--check", "--allow-pending", "--axross", self.axross)
        self.assertEqual(code, 0, text)
        self.assertIn(f"1 entries accepted, {len(self.hub.names) - 1} refused", text)
        self.assertIn("digest: sha256:<64 hex digits>", text)


if __name__ == "__main__":
    unittest.main()
