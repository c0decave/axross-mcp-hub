"""scripts/sign_catalog.py, scripts/ci_results.py and the sandbox-ai runners of scripts/axross_smoke.py: the
catalog is signed for sandbox-ai only when every published server is reviewed completely (reviews.json, for
exactly the files it is built from) and passed its smoke spec with sandbox-ai's own run line under Podman (and
under Bubblewrap where rootfs.json offers that form), for exactly the digest and rootfs it pins; the signature
verifies, and sandbox-ai's own check takes it (when SANDBOX_AI_CHECKOUT names a sandbox-ai checkout), fetched
from the very URL sandbox-ai reads this catalog from.

    python3 -m unittest discover -s tests -v
    SANDBOX_AI_CHECKOUT=/path/to/sandbox-ai python3 -m unittest discover -s tests
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sign = load("sign_catalog")
ci = load("ci_results")
rootfs = load("rootfs")
DIGEST = "sha256:" + "ab" * 32
SHA = "cd" * 32
IMAGE = f"ghcr.io/c0decave/axross-mcp-yara@{DIGEST}"
# Where sandbox-ai reads this catalog (sandbox/mcp.py CATALOGS): the files at the top of branch main.
RAW = "https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/"
ROOTFS = {"name": "yara", "image": IMAGE,
          "url": "https://github.com/c0decave/axross-mcp-hub/releases/download/rootfs-yara-cdcdcdcdcdcd/"
                 "rootfs-yara.tar.gz", "sha256": SHA, "size": 10,
          "entrypoint": ["/opt/venv/bin/python", "-I", "-u", "/opt/mcp/server.py"], "user": 10001,
          "workdir": "/tmp", "env": {"HOME": "/tmp"}}


def load_sandbox_ai():
    checkout = Path(os.environ["SANDBOX_AI_CHECKOUT"])
    spec = importlib.util.spec_from_file_location("sandbox_ai_mcp", checkout / "sandbox/mcp.py")
    mcp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mcp)
    return mcp


def unreview(root: Path, name: str) -> None:
    """Mark NAME not reviewed in the reviews.json under ROOT (a copy): every server of this repository is reviewed,
    the gate is tested with one taken back."""
    path = root / "reviews.json"
    reviews = json.loads(path.read_text())
    review = reviews["servers"][name]
    review.pop("files", None)
    review.update(reviewed=False, missing="a record that every shipped file was read in full (test)")
    path.write_text(json.dumps(reviews, indent=2) + "\n")


def report_of(name, runner, image, network="none", **changes):
    """A report as scripts/axross_smoke.py --report-dir writes it."""
    report = {"name": name, "image": image, "runner": runner, "network": network, "ok": True,
              "checks": [{"check": "tools_required", "ok": True}, {"check": "tools.json", "ok": True},
                         {"check": "call yara_scan_with_rules", "ok": True},
                         {"check": "refused yara_scan_with_rules", "ok": True}]}
    if runner.endswith("bwrap"):
        report["rootfs_sha256"] = SHA
    report.update(changes)
    return report


class HubCopy(unittest.TestCase):
    """A copy of the repository in which only yara is published (with a rootfs), and a throwaway signing key."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "hub"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "sandbox-ai"))  # CI checks sandbox-ai out beside us
        for stale in self.root.glob("*.sig"):
            stale.unlink()
        self.publish({"yara": DIGEST}, {"yara": ROOTFS})
        self.key = self.tmp / "key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(self.key)],
                       check=True)
        kind, key = (self.tmp / "key.pub").read_text().split()[:2]
        self.signers = self.tmp / "mcp-signers"
        # As sandbox/mcp-signers is written: comments, and a comment after the key.
        self.signers.write_text("# Keys that sign the MCP catalogs\n#\n"
                                f'mcp@sandbox-ai namespaces="sandbox-ai-mcp" {kind} {key} sandbox-ai-mcp\n')
        self.reports = self.tmp / "reports"
        self.reports.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def publish(self, images, rootfs_entries):
        digests = json.loads((self.root / "digests.json").read_text())
        digests["images"] = {name: images.get(name) for name in digests["images"]}
        digests["rootfs"] = rootfs_entries
        (self.root / "digests.json").write_text(json.dumps(digests, indent=2) + "\n")
        made = subprocess.run([sys.executable, str(self.root / "scripts/make_catalog.py"), "--root", str(self.root)],
                              capture_output=True, text=True)
        self.assertEqual(made.returncode, 0, made.stderr)

    def report(self, runner, folder=None, name="yara", image=IMAGE, **changes):
        folder = folder or self.reports
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"smoke-{name}-{runner}.json").write_text(json.dumps(report_of(name, runner, image, **changes)))

    def run_sign(self):
        return sign.main(["--root", str(self.root), "--key", str(self.key), "--reports", str(self.reports)])


@unittest.skipIf(not shutil.which("ssh-keygen"), "needs ssh-keygen")
class SignCatalog(HubCopy):
    def test_nothing_is_signed_without_passed_reports(self):
        self.assertEqual(self.run_sign(), 1)
        self.report("sandbox-ai-podman")
        self.assertEqual(self.run_sign(), 1, "the Bubblewrap report is missing (rootfs.json has a rootfs)")
        self.report("sandbox-ai-bwrap", ok=False, checks=[{"check": "call yara_scan_with_rules", "ok": False}])
        self.assertEqual(self.run_sign(), 1)
        self.report("sandbox-ai-bwrap", rootfs_sha256="ef" * 32)
        self.assertEqual(self.run_sign(), 1, "a report of another rootfs")
        self.report("sandbox-ai-bwrap")
        other = "ghcr.io/c0decave/axross-mcp-yara@sha256:" + "00" * 32
        self.report("sandbox-ai-podman", image=other)
        self.assertEqual(self.run_sign(), 1, "a report of another image")
        self.report("sandbox-ai-podman")
        bwrap = self.reports / "smoke-yara-sandbox-ai-bwrap.json"
        (self.reports / "smoke-yara-sandbox-ai-podman.json").write_bytes(bwrap.read_bytes())
        self.assertEqual(self.run_sign(), 1, "the report of the other runner under the podman name")
        cases = {"tools.json was not compared": [{"check": "tools_required", "ok": True},
                                                 {"check": "call yara_scan_with_rules", "ok": True},
                                                 {"check": "refused yara_scan_with_rules", "ok": True}],
                 "no real call": [{"check": "tools.json", "ok": True},
                                  {"check": "refused yara_scan_with_rules", "ok": True}],
                 "no refused call": [{"check": "tools.json", "ok": True},
                                     {"check": "call yara_scan_with_rules", "ok": True}],
                 "no checks at all": []}
        for why, checks in cases.items():
            self.report("sandbox-ai-podman", checks=checks)
            self.assertEqual(self.run_sign(), 1, why)
        self.report("sandbox-ai-podman", skipped="live_needs_network", ok=None, checks=[])
        self.assertEqual(self.run_sign(), 1, "a skipped run")
        self.assertFalse((self.root / "catalog.json.sig").exists())
        self.assertFalse((self.root / "rootfs.json.sig").exists())

    def test_a_server_without_rootfs_is_signed_for_podman_alone(self):
        """A server whose rootfs or Bubblewrap smoke test failed is published without a rootfs: its Podman report
        is enough, and rootfs.json vouches for no Bubblewrap form of it."""
        self.publish({"yara": DIGEST}, {})
        self.assertEqual(self.run_sign(), 1, "no Podman report yet")
        self.report("sandbox-ai-bwrap", ok=False, checks=[{"check": "call yara_scan_with_rules", "ok": False}])
        self.report("sandbox-ai-podman")
        self.assertEqual(self.run_sign(), 0, "a failed Bubblewrap report does not matter without a rootfs")
        self.assertNotIn("yara", json.loads((self.root / "rootfs.json").read_text())["rootfs"])

    def test_no_signature_with_more_network_than_the_entry_declares(self):
        """yara declares network none: a run with any network never vouches for it. crtsh is an allowlist entry:
        sandbox-ai gives it the full network (it has no egress proxy), so a full-network report is taken."""
        self.report("sandbox-ai-podman", network="full")
        self.report("sandbox-ai-bwrap")
        problems = sign.problems_of(self.root, self.reports)
        self.assertTrue(any("more network than it declares" in p for p in problems), problems)
        crtsh = "ghcr.io/c0decave/axross-mcp-crtsh@" + DIGEST
        self.assertEqual(sign.server_problems(self.reports, "crtsh", crtsh, None, "allowlist"),
                         ["crtsh: no smoke-crtsh-sandbox-ai-podman.json under " + str(self.reports)])
        self.report("sandbox-ai-podman", name="crtsh", image=crtsh, network="full")
        self.assertEqual(sign.server_problems(self.reports, "crtsh", crtsh, None, "allowlist"), [])

    def test_no_signature_for_a_rootfs_the_catalog_does_not_publish(self):
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-bwrap")
        document = json.loads((self.root / "rootfs.json").read_text())
        document["rootfs"]["capa"] = dict(document["rootfs"]["yara"])
        (self.root / "rootfs.json").write_text(json.dumps(document, indent=2) + "\n")
        problems = sign.problems_of(self.root, self.reports)
        self.assertTrue(any("capa" in p and "does not" in p for p in problems), problems)
        self.assertEqual(self.run_sign(), 1)

    def test_no_reports_folder_no_signature(self):
        self.assertEqual(sign.main(["--root", str(self.root), "--key", str(self.key),
                                    "--reports", str(self.tmp / "nothing")]), 1)
        self.assertFalse((self.root / "catalog.json.sig").exists())

    def test_the_catalog_artifact_as_downloaded(self):
        """The catalog artifact (or ci-digests.tar.gz of the pre-release) keeps the reports in ci-digests/:
        --reports DIR finds them; two copies of one report are refused (which run is it?)."""
        nested = self.reports / "ci-digests"
        self.report("sandbox-ai-podman", folder=nested)
        self.report("sandbox-ai-bwrap", folder=nested)
        self.assertEqual(self.run_sign(), 0)
        self.report("sandbox-ai-bwrap", folder=self.reports / "another-run")
        (self.root / "catalog.json.sig").unlink()
        self.assertEqual(self.run_sign(), 1)

    def test_signed_and_verified(self):
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-bwrap")
        self.assertEqual(self.run_sign(), 0)
        self.assertEqual(sign.main(["--root", str(self.root), "--verify", "--signers", str(self.signers)]), 0)
        (self.root / "rootfs.json").write_text((self.root / "rootfs.json").read_text().replace(SHA, "ef" * 32))
        self.assertEqual(sign.main(["--root", str(self.root), "--verify", "--signers", str(self.signers)]), 1)

    def test_a_stale_catalog_is_not_signed(self):
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-bwrap")
        catalog = self.root / "catalog.json"
        catalog.write_text(catalog.read_text().replace('"title": "YARA', '"title": "Something else', 1))
        self.assertEqual(self.run_sign(), 1)


@unittest.skipIf(not shutil.which("ssh-keygen"), "needs ssh-keygen")
class ReviewGate(HubCopy):
    """Only servers whose shipped MCP code we reviewed completely are signed, and only as reviewed."""

    def test_a_server_not_reviewed_is_never_signed(self):
        unreview(self.root, "mcpcap")
        mcpcap = "ghcr.io/c0decave/axross-mcp-mcpcap@" + DIGEST
        self.publish({"yara": DIGEST, "mcpcap": DIGEST}, {})
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-podman", name="mcpcap", image=mcpcap)
        problems = sign.problems_of(self.root, self.reports)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("mcpcap: not reviewed completely; missing: "), problems)
        self.assertEqual(self.run_sign(), 1)
        self.assertEqual(sign.main(["--root", str(self.root), "--record-review", "mcpcap"]), 1,
                         "recording files never marks a server reviewed")
        self.publish({"yara": DIGEST}, {})  # mcpcap pending: the rest is signed
        self.assertEqual(self.run_sign(), 0)

    def test_a_change_since_the_review_is_not_signed_until_recorded(self):
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-bwrap")
        server = self.root / "servers/yara/src/server.py"
        server.write_text(server.read_text() + "\n# changed\n")
        problems = sign.problems_of(self.root, self.reports)
        self.assertEqual(problems, ["yara: src/server.py changed since its review: review the change, then "
                                    "scripts/sign_catalog.py --record-review yara"])
        (self.root / "servers/yara/src/extra.py").write_text("")
        self.assertIn("src/extra.py", sign.review_problems(self.root, "yara")[0], "a new shipped file counts")
        self.assertEqual(sign.main(["--root", str(self.root), "--record-review", "yara"]), 0)
        self.assertEqual(self.run_sign(), 0)

    def test_a_changed_patch_is_a_changed_shipped_file(self):
        """Upstream code fetched at a pinned commit and patched here: the patches are part of what was reviewed."""
        self.assertEqual(sign.review_problems(self.root, "radare2"), [])
        patch = next((self.root / "servers/radare2/patches").glob("*.patch"))
        patch.write_text(patch.read_text() + "\n")
        problems = sign.review_problems(self.root, "radare2")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(f"patches/{patch.name} changed since its review", problems[0])
        (self.root / "servers/radare2/patches/0002-new.patch").write_text("")
        self.assertIn("patches/0002-new.patch", sign.review_problems(self.root, "radare2")[0], "a new patch counts")

    def test_without_reviews_json_nothing_is_signed(self):
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-bwrap")
        (self.root / "reviews.json").unlink()
        self.assertEqual(self.run_sign(), 1)


class TheReviewsOfThisRepository(unittest.TestCase):
    """reviews.json names every server: reviewed (with its record and the files reviewed) or not, and why."""

    def test_every_server_has_a_review_state(self):
        reviews = sign.load_reviews(ROOT)["servers"]
        servers = sorted(p.parent.name for p in (ROOT / "servers").glob("*/server.json"))
        self.assertEqual(sorted(reviews), servers)
        for name, review in reviews.items():
            self.assertIs(type(review.get("reviewed")), bool, name)
            record = ROOT / review["record"]
            self.assertTrue(record.is_file(), name)
            self.assertIn("## Audit", record.read_text(encoding="utf-8"), name)
            self.assertTrue(review.get("mcp_code"), name)
            if review["reviewed"]:
                self.assertEqual(sorted(review["files"]), sorted(sign.shipped_files(ROOT, name)),
                                 f"{name}: the review covers every shipped file")
                self.assertIn("Dockerfile", review["files"], name)
                if (ROOT / "servers" / name / "src").is_dir():
                    self.assertIn("src/server.py", review["files"], name)
                else:  # MCP code fetched upstream at the commit the Dockerfile pins, patched by patches/
                    self.assertRegex((ROOT / "servers" / name / "Dockerfile").read_text(),
                                     r"(?m)^ARG \w*COMMIT=[0-9a-f]{40}$", name)
            else:
                self.assertTrue(review.get("missing"), f"{name}: why it is not reviewed")
                self.assertNotIn("files", review, name)


class CiResults(unittest.TestCase):
    """scripts/ci_results.py: the catalog job takes a server only when its image job passed, its reports pass
    sign_catalog.py's check for what that job pushed, and its review is recorded."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.folder = self.tmp / "ci-digests"
        self.folder.mkdir()
        self.root = self.tmp / "hub"  # a copy in which mcpcap is not reviewed
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__", "sandbox-ai"))
        unreview(self.root, "mcpcap")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def job(self, name, *, passed=True, podman=True, bwrap=None):
        image = f"ghcr.io/c0decave/axross-mcp-{name}"
        write = lambda file, data: (self.folder / file).write_text(json.dumps(data))  # noqa: E731
        if passed:
            write(f"result-{name}.json", {"name": name, "passed": True})
        write(f"digest-{name}.json", {"name": name, "image": image, "digest": DIGEST})
        if podman:
            write(f"smoke-{name}-sandbox-ai-podman.json", report_of(name, "sandbox-ai-podman", f"{image}@{DIGEST}"))
        if bwrap is not None:
            write(f"rootfs-{name}.json", {**ROOTFS, "name": name, "image": f"{image}@{DIGEST}"})
            write(f"smoke-{name}-sandbox-ai-bwrap.json",
                  report_of(name, "sandbox-ai-bwrap", f"{image}@{DIGEST}", ok=bwrap))

    def test_passed_and_reviewed_only(self):
        self.job("yara", bwrap=True)
        self.job("capa")                                  # Podman only
        self.job("binwalk", bwrap=False)                  # a kept rootfs whose Bubblewrap report failed
        self.job("nmap", passed=False)
        self.job("tshark", podman=False)
        self.job("mcpcap", bwrap=True)                    # passed, not reviewed
        out = self.tmp / "passed.txt"
        self.assertEqual(ci.main([str(self.folder), "--root", str(self.root), "--out", str(out)]), 0)
        self.assertEqual(out.read_text().split(), ["capa", "yara"])
        self.assertTrue(ci.server_result(self.folder, "mcpcap", "none", self.root)[0]
                        .startswith("not reviewed completely"))
        self.assertEqual(ci.server_result(self.folder, "yara", "none", self.root), [])

    def test_no_server_no_catalog(self):
        self.job("mcpcap")
        self.assertEqual(ci.main([str(self.folder), "--root", str(self.root), "--out", str(self.tmp / "passed.txt")]),
                         1)


class OnlyTheServersThatPassed(unittest.TestCase):
    """make_catalog.py --ci-digests DIR --only ...: the others become pending and lose their rootfs."""

    def test_only(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            root = tmp / "hub"
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", "sandbox-ai"))
            folder = tmp / "ci"
            folder.mkdir()
            for name in ("yara", "capa"):
                image = f"ghcr.io/c0decave/axross-mcp-{name}"
                (folder / f"digest-{name}.json").write_text(json.dumps({"name": name, "image": image,
                                                                        "digest": DIGEST}))
                (folder / f"rootfs-{name}.json").write_text(json.dumps({**ROOTFS, "name": name,
                                                                        "image": f"{image}@{DIGEST}"}))
            run = subprocess.run([sys.executable, str(root / "scripts/make_catalog.py"), "--root", str(root),
                                  "--ci-digests", str(folder), "--only", "yara", "--write-digests"],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            catalog = json.loads((root / "catalog.json").read_text())
            pinned = {e["name"]: e.get("digest") for e in catalog["entries"]}
            self.assertEqual(pinned["yara"], DIGEST)
            self.assertEqual([n for n, d in pinned.items() if d], ["yara"], "everything else is pending")
            self.assertEqual(sorted(json.loads((root / "rootfs.json").read_text())["rootfs"]), ["yara"])
            check = subprocess.run([sys.executable, str(root / "scripts/make_catalog.py"), "--root", str(root),
                                    "--check", "--allow-pending"], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class FakeSession:
    """A server that answers as the spec expects: initialize, tools/list of tools.json, each call's text."""

    answers: dict = {}
    started: list = []

    def __init__(self, argv, env_fd, env=None):
        FakeSession.started.append((argv, env_fd))

    def send(self, message):
        pass

    def request(self, method, params, timeout):
        if method == "initialize":
            return {"result": {"serverInfo": {"name": "fake"}}}
        if method == "tools/list":
            return {"result": {"tools": [{"name": t} for t in self.answers["tools"]]}}
        text = self.answers.get((params["name"], json.dumps(params["arguments"], sort_keys=True)), "done")
        return {"result": {"content": [{"type": "text", "text": text}]}}

    def close(self):
        return ""


@unittest.skipIf(not shutil.which("ssh-keygen"), "needs ssh-keygen")
class AxrossSmokeReports(HubCopy):
    """scripts/axross_smoke.py --runner sandbox-ai-... --report-dir writes the reports sign_catalog.py takes: the
    hub's smoke spec of yara (files in its mounted folder) with sandbox-ai's argv, the server faked."""

    def run_spec(self, runner, image=IMAGE, answer=True):
        smoke = load("axross_smoke")
        st = load("smoke_test")
        spec = json.loads((ROOT / "tests/axross-smoke.json").read_text())
        (server,) = [s for s in spec["servers"] if s["name"] == "yara"]
        FakeSession.answers = {"tools": json.loads((ROOT / "servers/yara/tools.json").read_text())["tools"]}
        for call in [server["call"], server["refused"]] if answer else []:
            FakeSession.answers[(call["tool"], json.dumps(call.get("args", {}), sort_keys=True))] = \
                call["expect_substring"]
        FakeSession.started = []
        seen = {}

        def sandbox_ai_argv(runner_, checkout, image_, network, mounts, env, rootfs_=None, meta=None):
            seen.update(runner=runner_, image=image_, network=network, mounts=mounts)
            if os.environ.get("SANDBOX_AI_CHECKOUT") and runner_ == "sandbox-ai-podman":
                return st.sandbox_ai_argv(runner_, checkout, image_, network, mounts, env, rootfs_, meta)
            return ["sandbox-ai-run"], {}, ({"image": image_} if runner_.endswith("podman")
                                            else {"rootfs_sha256": meta["sha256"]})

        fake = types.SimpleNamespace(**{k: getattr(st, k) for k in dir(st) if not k.startswith("__")})
        fake.Session, fake.sandbox_ai_argv = FakeSession, sandbox_ai_argv
        folder = self.tmp / "rootfs-out"
        folder.mkdir(exist_ok=True)
        (folder / "rootfs-yara.json").write_text(json.dumps({"name": "yara", "sha256": SHA, "entrypoint": ["/x"]}))
        opts = argparse.Namespace(runner=runner, sandbox_ai=os.environ.get("SANDBOX_AI_CHECKOUT", "/nowhere"),
                                  rootfs_dir=str(folder), engine="podman", axross=None, target_host=None,
                                  call_retries=1, call_backoff=0.0)
        report = smoke.run_one(server, spec, image, opts, fake)
        self.assertEqual(seen["runner"], runner)
        self.assertEqual(seen["image"], image)
        self.assertEqual(seen["network"], "none")
        self.assertEqual([target for _, target, _ in seen["mounts"]], ["/work"])
        self.assertEqual(FakeSession.started[0][1], None, "sandbox-ai's own runner: no axross env pipe")
        (self.reports / f"smoke-yara-{runner}.json").write_text(json.dumps(report))
        return report

    def test_its_reports_are_signed(self):
        podman = self.run_spec("sandbox-ai-podman")
        self.assertTrue(podman["ok"], podman)
        self.assertEqual(podman["network"], "none")
        if os.environ.get("SANDBOX_AI_CHECKOUT"):
            self.assertEqual(podman["argv"][:2], ["podman", "run"])
            self.assertIn("--network=none", podman["argv"])
            self.assertTrue(any(a.endswith(":/work:ro") for a in podman["argv"]), podman["argv"])
        self.assertEqual(self.run_sign(), 1, "the Bubblewrap report is missing")
        bwrap = self.run_spec("sandbox-ai-bwrap")
        self.assertEqual(bwrap["rootfs_sha256"], SHA)
        self.assertEqual(self.run_sign(), 0)
        self.assertEqual(sign.main(["--root", str(self.root), "--verify", "--signers", str(self.signers)]), 0)

    def test_a_failed_call_is_not_signed(self):
        self.run_spec("sandbox-ai-podman")
        report = self.run_spec("sandbox-ai-bwrap", answer=False)  # every call answers "done"
        self.assertFalse(report["ok"])
        call = [c for c in report["checks"] if c["check"].startswith("call ")][0]
        self.assertEqual(call["attempts"], 2, "the real call is repeated --call-retries times")
        refused = [c for c in report["checks"] if c["check"].startswith("refused ")][0]
        self.assertEqual(refused["attempts"], 1, "a refusal must come at the first try")
        self.assertEqual(self.run_sign(), 1)

    def test_a_report_of_another_build_is_not_signed(self):
        self.run_spec("sandbox-ai-podman", image="ghcr.io/c0decave/axross-mcp-yara@sha256:" + "00" * 32)
        self.run_spec("sandbox-ai-bwrap")
        self.assertEqual(self.run_sign(), 1)


@unittest.skipIf(not shutil.which("ssh-keygen"), "needs ssh-keygen")
@unittest.skipUnless(os.environ.get("SANDBOX_AI_CHECKOUT"), "SANDBOX_AI_CHECKOUT names a sandbox-ai checkout")
class SandboxAiTakesIt(HubCopy):
    def test_sandbox_ai_takes_the_signature(self):
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-bwrap")
        self.assertEqual(self.run_sign(), 0)
        mcp = load_sandbox_ai()
        keys = mcp.release_keys()
        trusted = keys.parse(self.signers.read_text(), "test", keys.MCP)
        source = str(self.root / "catalog.json")
        verdict = mcp.catalog_signature(source, Path(source).read_bytes(), keys=trusted)
        self.assertEqual(verdict["state"], "good", verdict)

    def test_sandbox_ai_reads_it_where_it_is_published(self):
        """sandbox-ai fetches catalog.json, catalog.json.sig, rootfs.json and rootfs.json.sig from main of
        github.com/c0decave/axross-mcp-hub: the files sign_catalog.py writes at the top of the repository."""
        self.report("sandbox-ai-podman")
        self.report("sandbox-ai-bwrap")
        self.assertEqual(self.run_sign(), 0)
        mcp = load_sandbox_ai()
        self.assertIn(("hub", RAW + "catalog.json"), mcp.CATALOGS)
        fetched = []

        def fetch(url):  # the repository's main branch as raw.githubusercontent.com serves it
            self.assertTrue(url.startswith(RAW), url)
            fetched.append(url[len(RAW):])
            return (self.root / url[len(RAW):]).read_bytes()

        keys = mcp.release_keys()
        saved = keys.MCP["signers"]
        try:
            keys.MCP["signers"] = self.signers
            found, problems = mcp.catalog_entries([("hub", RAW + "catalog.json")], fetch=fetch)
            self.assertEqual(problems, [])
            self.assertEqual(fetched, ["catalog.json", "catalog.json.sig", "rootfs.json", "rootfs.json.sig"])
            (entry,) = [e for _, e in found if e["name"] == "yara"]
            self.assertEqual(entry["_signature"]["state"], "good")
            self.assertEqual(entry["rootfs"]["sha256"], SHA)
            self.assertEqual(mcp.check_signature(entry)["signed_by"], entry["_signature"]["signer"])
            (pending,) = [e for _, e in found if e["name"] == "mcpcap"]
            with self.assertRaises(ValueError):  # signed catalog, but no digest: never added
                mcp.definition_from_entry(pending, mounts=[f"/work={self.tmp}"])
            # The real mcp-signers do not trust a throwaway key: the same files are refused there.
            keys.MCP["signers"] = Path(os.environ["SANDBOX_AI_CHECKOUT"]) / "sandbox/mcp-signers"
            (entry,) = [e for _, e in mcp.catalog_entries([("hub", RAW + "catalog.json")], fetch=fetch)[0]
                        if e["name"] == "yara"]
            self.assertEqual(entry["_signature"]["state"], "bad")
            with self.assertRaises(ValueError):
                mcp.check_signature(entry)
        finally:
            keys.MCP["signers"] = saved


class WorkflowMakesTheReports(unittest.TestCase):
    """.github/workflows/build.yml builds every server and writes and uploads the reports sign_catalog.py wants."""

    def test_every_server_and_both_reports(self):
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        matrix = re.search(r"^\s*server: \[([^\]]*)\]", workflow, re.M)
        self.assertIsNotNone(matrix)
        built = sorted(name.strip() for name in matrix[1].replace("\n", " ").split(",") if name.strip())
        self.assertEqual(built, sorted(p.parent.name for p in (ROOT / "servers").glob("*/server.json")))
        for runner in sign.RUNNERS:
            self.assertIn(f"--runner {runner} ", workflow)
            self.assertIn(f"reports/smoke-${{{{ matrix.server }}}}-{runner}.json", workflow, "uploaded")
        self.assertEqual(workflow.count("--report-dir reports"), 2, "both runners write their reports")
        self.assertIn("ci-digests/**/smoke-*.json", workflow, "the catalog artifact carries the reports")
        self.assertIn("scripts/ci_results.py ci-digests --out passed.txt", workflow)
        self.assertIn("--only $(cat passed.txt)", workflow)
        self.assertIn("rootfs.json", workflow)
        self.assertIn('tag="ci-catalog-$RUN_ID"', workflow)
        for line in workflow.splitlines():  # every action pinned by commit
            if re.match(r"\s*(- )?uses: ", line):
                self.assertRegex(line, r"@[0-9a-f]{40} # v\d", line)


class RootfsFacts(unittest.TestCase):
    def test_what_runs_it(self):
        facts = rootfs.run_facts({"Entrypoint": ["/opt/venv/bin/python", "-I"], "Cmd": ["/opt/mcp/server.py"],
                                  "User": "10001:10001", "WorkingDir": "/tmp",
                                  "Env": ["HOME=/tmp", "PATH=/usr/bin", "bad name=x"]})
        self.assertEqual(facts, {"entrypoint": ["/opt/venv/bin/python", "-I", "/opt/mcp/server.py"],
                                 "user": 10001, "workdir": "/tmp", "env": {"HOME": "/tmp", "PATH": "/usr/bin"}})
        for config in ({"Entrypoint": ["python3"], "User": "10001"}, {"Entrypoint": ["/x"], "User": "root"},
                       {"Entrypoint": ["/x"], "User": "0"}, {"Entrypoint": [], "User": "1"}):
            with self.assertRaises(ValueError):
                rootfs.run_facts(config)

    def test_every_image_has_a_numeric_user_other_than_root(self):
        """sandbox-ai runs the rootfs as the image's USER: every Dockerfile must name a numeric one."""
        for dockerfile in sorted((ROOT / "servers").glob("*/Dockerfile")):
            users = re.findall(r"^USER\s+(\S+)", dockerfile.read_text(), re.M)
            self.assertTrue(users, dockerfile)
            self.assertRegex(users[-1], r"^[1-9][0-9]{0,4}(:[0-9]+)?$", dockerfile)


class SmokeAnnotation(unittest.TestCase):
    """A failed smoke run says why in an error annotation (job logs are not always readable)."""

    def test_the_annotation_names_the_reason_on_one_escaped_line(self):
        smoke = load("smoke_test")
        line = smoke.annotation({"name": "yara", "runner": "sandbox-ai-bwrap", "image": "i@sha256:1",
                                 "exception": "RuntimeError: 50% gone", "stderr_tail": "a\nb",
                                 "checks": [{"check": "tools_required", "ok": False, "missing": ["yara_scan"]},
                                            {"check": "call x", "ok": True}]})
        self.assertTrue(line.startswith("::error title=smoke yara (sandbox-ai-bwrap)::"))
        self.assertEqual(line.count("\n"), 0)
        for part in ("RuntimeError: 50%25 gone", "failed: tools_required", "yara_scan", "stderr: a%0Ab"):
            self.assertIn(part, line)
        self.assertNotIn("call x", line)


@unittest.skipUnless(os.environ.get("SANDBOX_AI_CHECKOUT"), "SANDBOX_AI_CHECKOUT names a sandbox-ai checkout")
class SmokeWithSandboxAi(unittest.TestCase):
    """smoke_test.py's sandbox_ai_argv starts a server with sandbox-ai's own run lines."""

    def test_the_podman_runner_keeps_podmans_image_store(self):
        smoke = load("smoke_test")
        before = os.environ.pop("XDG_DATA_HOME", None)
        try:
            _, env, _ = smoke.sandbox_ai_argv("sandbox-ai-podman", os.environ["SANDBOX_AI_CHECKOUT"], IMAGE,
                                              "allowlist", [], {})
            self.assertNotIn("XDG_DATA_HOME", os.environ)
            self.assertNotIn("XDG_DATA_HOME", env)
        finally:
            if before is not None:
                os.environ["XDG_DATA_HOME"] = before

    def test_the_run_lines_are_sandbox_ais(self):
        import hashlib
        import io
        import tarfile
        smoke = load("smoke_test")
        checkout = os.environ["SANDBOX_AI_CHECKOUT"]
        tmp = Path(tempfile.mkdtemp())
        before = os.environ.get("XDG_DATA_HOME")
        os.environ["XDG_DATA_HOME"] = str(tmp / "data")
        try:
            folder = tmp / "work"
            folder.mkdir()
            argv, env, facts = smoke.sandbox_ai_argv("sandbox-ai-podman", checkout, IMAGE, "none",
                                                     [(str(folder), "/work", False)], {})
            self.assertEqual(argv[:2], ["podman", "run"])
            for flag in ("--cap-drop=ALL", "--read-only", "--security-opt=no-new-privileges", "--network=none",
                         "--user=0:0", f"--volume={folder}:/work:ro"):
                self.assertIn(flag, argv)
            self.assertEqual(argv[-1], IMAGE)
            self.assertEqual(facts, {"image": IMAGE})
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                info = tarfile.TarInfo("server")
                info.size, info.mode = 3, 0o755
                tar.addfile(info, io.BytesIO(b"#!x"))
            archive = tmp / "rootfs.tar.gz"
            archive.write_bytes(buffer.getvalue())
            meta = {"sha256": hashlib.sha256(buffer.getvalue()).hexdigest(), "entrypoint": ["/server"],
                    "user": 10001, "workdir": "/tmp", "env": {"HOME": "/tmp"}}
            argv, env, facts = smoke.sandbox_ai_argv("sandbox-ai-bwrap", checkout, IMAGE, "none", [], {},
                                                     str(archive), meta)
            self.assertEqual(facts, {"rootfs_sha256": meta["sha256"]})
            definition = json.loads(Path(argv[-1]).read_text())
            self.assertTrue(Path(definition["rootfs"]["path"], "server").is_file())
            meta["sha256"] = "00" * 32
            with self.assertRaises(ValueError):
                smoke.sandbox_ai_argv("sandbox-ai-bwrap", checkout, IMAGE, "none", [], {}, str(archive), meta)
        finally:
            if before is None:
                os.environ.pop("XDG_DATA_HOME", None)
            else:
                os.environ["XDG_DATA_HOME"] = before
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
