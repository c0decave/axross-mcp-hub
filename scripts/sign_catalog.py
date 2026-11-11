#!/usr/bin/env python3
"""Sign catalog.json and rootfs.json for sandbox-ai: the statement that every published server of this catalog
was reviewed completely by us and works with sandbox-ai, for exactly the image digest (and rootfs) it pins.

    scripts/sign_catalog.py --key ~/.config/sandbox-ai/mcp-signing-key --reports DIR
    scripts/sign_catalog.py --verify --signers /path/to/sandbox-ai/sandbox/mcp-signers
    scripts/sign_catalog.py --record-review NAME...     # after reviewing a change of NAME's shipped files

Before it signs, for every entry with a digest it requires

- its review (reviews.json): ``"reviewed": true``, its record (servers/<name>/PROVENANCE.md) there, and the
  files that decide what the image ships (Dockerfile, requirements*.txt, src/, patches/) exactly the ones reviewed, by
  SHA-256. Only servers whose shipped MCP server code we reviewed completely ourselves are signed; a server
  changed since its review is not signed until the change is reviewed and recorded (--record-review);
- in DIR or a folder below it (the "catalog" artifact of the build workflow keeps them in ci-digests/;
  ``gh run download RUN -n catalog -D DIR``, or the pre-release ci-catalog-RUN):

    smoke-<name>-sandbox-ai-podman.json   ok, runner sandbox-ai-podman, image IMAGE@DIGEST of the catalog
    smoke-<name>-sandbox-ai-bwrap.json    only when rootfs.json has a rootfs for it: ok, runner
                                          sandbox-ai-bwrap, the same image, rootfs_sha256 of rootfs.json

  each written by scripts/axross_smoke.py (the server's spec of tests/axross-smoke.json, started with
  sandbox-ai's own run line) with every check passed: tools/list offered exactly tools.json, the real call
  answered with its expected text, the refused call was refused; run with no more network than the entry
  declares;
- catalog.json and rootfs.json current (scripts/make_catalog.py --check; no rootfs for a server the catalog
  does not publish).

Then it writes catalog.json.sig and rootfs.json.sig: SSH signatures (ssh-keygen -Y sign) in the namespace
sandbox-ai-mcp, which sandbox-ai checks against its sandbox/mcp-signers (principal mcp@sandbox-ai) before
`sandbox-ai mcp add` takes an entry. The key never leaves your machine: sign after the CI run, then commit
catalog.json, rootfs.json, digests.json and both .sig. Standard library only (ssh-keygen, OpenSSH 8.1 or newer).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAMESPACE = "sandbox-ai-mcp"
PRINCIPAL = "mcp@sandbox-ai"
RUNNERS = ("sandbox-ai-podman", "sandbox-ai-bwrap")
REVIEWS = "reviews.json"
#: How much network a run had. A report may have had less than the entry declares, never more. "allowlist"
#: counts as "full": sandbox-ai has no per-server egress proxy, so it gives an allowlist entry the full network,
#: which is what CI tests it with.
NETWORK_ORDER = {"none": 0, "allowlist": 1, "full": 1}


# --- the review ------------------------------------------------------------------------------------------

def shipped_files(root: Path, name: str) -> dict[str, str]:
    """{path below servers/NAME: sha256} of the files that decide what NAME's image ships: its Dockerfile (base,
    pinned upstream commits and packages), requirements*.txt (the hash-locked Python packages), src/ (the
    MCP server code) and patches/ (this repository's changes to upstream code fetched at a pinned commit)."""
    folder = root / "servers" / name
    paths = [folder / "Dockerfile", *sorted(folder.glob("requirements*.txt")),
             *(p for sub in ("src", "patches")
               for p in sorted((folder / sub).rglob("*")) if p.is_file() and "__pycache__" not in p.parts)]
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths if p.is_file()}


def load_reviews(root: Path) -> dict:
    data = json.loads((root / REVIEWS).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        raise ValueError(f"{REVIEWS}: needs an object 'servers' of name -> review")
    return data


def review_problems(root: Path, name: str) -> list[str]:
    """Why NAME may not be vouched for as reviewed (empty: it may). Shared with scripts/ci_results.py."""
    try:
        review = load_reviews(root)["servers"].get(name)
    except (OSError, ValueError) as exc:
        return [f"{name}: {REVIEWS} cannot be read ({exc})"]
    if not isinstance(review, dict):
        return [f"{name}: not in {REVIEWS}: nobody recorded a complete review of it"]
    if review.get("reviewed") is not True:
        return [f"{name}: not reviewed completely; missing: {review.get('missing') or 'a record of the review'}"]
    record = review.get("record")
    if not isinstance(record, str) or not (root / record).is_file():
        return [f"{name}: its review record {record!r} is not in the repository"]
    recorded = review.get("files")
    if not isinstance(recorded, dict) or not recorded:
        return [f"{name}: {REVIEWS} has no files for its review"]
    current = shipped_files(root, name)
    changed = sorted(path for path in set(recorded) | set(current) if recorded.get(path) != current.get(path))
    if changed:
        return [f"{name}: {', '.join(changed)} changed since its review: review the change, then "
                f"scripts/sign_catalog.py --record-review {name}"]
    return []


def record_review(root: Path, names: list[str]) -> list[str]:
    """Record the current shipped files of NAMES as reviewed (each must already be "reviewed": true: marking a
    server reviewed at all is a deliberate edit of reviews.json, with its record)."""
    data = load_reviews(root)
    problems = []
    for name in names:
        review = data["servers"].get(name)
        if not (root / "servers" / name / "server.json").is_file():
            problems.append(f"{name}: no such server")
        elif not isinstance(review, dict) or review.get("reviewed") is not True:
            problems.append(f"{name}: not marked \"reviewed\": true in {REVIEWS} (edit it with the record of "
                            "the complete review first)")
        else:
            review["files"] = shipped_files(root, name)
    if not problems:
        (root / REVIEWS).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return problems


# --- the smoke reports -----------------------------------------------------------------------------------

def find_report(reports: Path, name: str, runner: str) -> tuple[dict | None, str | None]:
    """(the RUNNER report of NAME under REPORTS, None) or (None, why there is no usable one)."""
    wanted_name = f"smoke-{name}-{runner}.json"
    found = sorted(reports.rglob(wanted_name))
    if len(found) > 1:
        return None, f"{name}: {wanted_name} is there {len(found)} times under {reports} (one CI run only)"
    try:
        report = json.loads(found[0].read_text(encoding="utf-8"))
    except (IndexError, OSError, ValueError):
        return None, f"{name}: no {wanted_name} under {reports}"
    if not isinstance(report, dict) or report.get("runner") != runner or report.get("name") != name:
        return None, f"{name}: {wanted_name} is not the {runner} report of {name}"
    return report, None


def _passed(checks: list, prefix: str) -> bool:
    return any(str(c.get("check", "")).startswith(prefix) and c.get("ok") is True for c in checks)


def server_problems(reports: Path, name: str, image: str, rootfs_sha256: str | None, network) -> list[str]:
    """Why NAME, published as IMAGE (IMAGE@DIGEST) with network NETWORK, may not be vouched for: its Podman report,
    and its Bubblewrap report for the rootfs ROOTFS_SHA256 when it has one (None: Podman alone), must have passed
    under REPORTS for exactly these. Shared with scripts/ci_results.py, which picks a CI run's servers by it."""
    problems = []
    # Bubblewrap is vouched for only where rootfs.json offers that form: a server whose Bubblewrap smoke test
    # failed is published for Podman alone (its rootfs left out by the build), never signed for Bubblewrap.
    for runner in (r for r in RUNNERS if r != "sandbox-ai-bwrap" or rootfs_sha256 is not None):
        report, problem = find_report(reports, name, runner)
        if problem:
            problems.append(problem)
            continue
        checks = report.get("checks")
        checks = checks if isinstance(checks, list) and all(isinstance(c, dict) for c in checks) else []
        if report.get("skipped"):
            problems.append(f"{name}: {runner} was skipped ({report['skipped']})")
        elif report.get("ok") is not True or not checks or not all(c.get("ok") is True for c in checks):
            failed = [c.get("check") for c in checks if c.get("ok") is not True]
            problems.append(f"{name}: {runner} failed ({', '.join(map(str, failed)) or report.get('exception')})")
        elif not _passed(checks, "tools.json"):
            problems.append(f"{name}: {runner} did not compare tools/list with tools.json")
        elif not _passed(checks, "call "):
            # A handshake and a tool list say nothing about the tool: the signature vouches for a server whose
            # real call of tests/axross-smoke.json answered.
            problems.append(f"{name}: {runner} made no real tool call")
        elif not _passed(checks, "refused "):
            problems.append(f"{name}: {runner} did not show that the server refuses a bad call")
        elif NETWORK_ORDER.get(str(report.get("network")), len(NETWORK_ORDER)) > NETWORK_ORDER.get(network, 0):
            problems.append(f"{name}: the {runner} report ran it with network {report.get('network')}, "
                            f"the entry says {network}: a server is never vouched for with "
                            "more network than it declares")
        elif report.get("image") != image:
            problems.append(f"{name}: the {runner} report is of {report.get('image')}, the catalog pins {image}")
        elif runner == "sandbox-ai-bwrap" and report.get("rootfs_sha256") != rootfs_sha256:
            problems.append(f"{name}: the bwrap report is of rootfs {report.get('rootfs_sha256')}, "
                            f"rootfs.json says {rootfs_sha256}")
    return problems


def problems_of(root: Path, reports: Path) -> list[str]:
    """What stands in the way of signing: a stale catalog, a server not reviewed (or changed since), a server
    without its passed reports (Podman always, Bubblewrap where rootfs.json has its rootfs)."""
    problems = []
    check = subprocess.run([sys.executable, str(root / "scripts/make_catalog.py"), "--root", str(root), "--check",
                            "--allow-pending"], capture_output=True, text=True)
    if check.returncode != 0:
        problems.append("the catalog is not current: " + (check.stderr or check.stdout).strip())
    catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    rootfs = json.loads((root / "rootfs.json").read_text(encoding="utf-8")).get("rootfs", {})
    published = [e for e in catalog.get("entries", []) if e.get("digest")]
    if not published:
        problems.append("no entry has a digest yet: nothing to vouch for")
    for entry in published:
        problems.extend(review_problems(root, entry["name"]))
    if not reports.is_dir():
        problems.append(f"{reports}: not a folder of smoke reports")
        return problems
    for entry in published:
        name = entry["name"]
        problems.extend(server_problems(reports, name, f"{entry['image']}@{entry['digest']}",
                                        (rootfs.get(name) or {}).get("sha256") if name in rootfs else None,
                                        entry.get("network")))
    stale = sorted(set(rootfs) - {e["name"] for e in published})
    if stale:
        problems.append(f"rootfs.json pins a rootfs for {', '.join(stale)}, which the catalog does not "
                        "publish: run scripts/make_catalog.py")
    return problems


# --- signing ---------------------------------------------------------------------------------------------

def sign(path: Path, key: str) -> Path:
    result = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", NAMESPACE], input=path.read_bytes(),
                            stdout=subprocess.PIPE)
    if result.returncode != 0 or b"BEGIN SSH SIGNATURE" not in result.stdout:
        raise RuntimeError(f"ssh-keygen -Y sign -f {key} failed")
    signature = path.with_name(path.name + ".sig")
    signature.write_bytes(result.stdout)
    return signature


def verify(path: Path, signers: Path) -> bool:
    signature = path.with_name(path.name + ".sig")
    if not signature.exists():
        print(f"{signature.name}: missing", file=sys.stderr)
        return False
    with tempfile.TemporaryDirectory() as tmp:
        allowed = Path(tmp, "allowed_signers")
        allowed.write_text("".join(line + "\n" for line in signers.read_text().splitlines()
                                   if line.strip() and not line.startswith("#")))
        result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", PRINCIPAL, "-n", NAMESPACE,
                                 "-s", str(signature)], input=path.read_bytes(), capture_output=True)
    print(f"{path.name}: " + ("good" if result.returncode == 0 else (result.stderr or result.stdout).decode().strip()))
    return result.returncode == 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--key", help="the private key (or the .pub of a key in ssh-agent)")
    parser.add_argument("--reports", type=Path, help="the smoke reports of the CI run")
    parser.add_argument("--verify", action="store_true", help="check the signatures instead")
    parser.add_argument("--signers", type=Path, help="with --verify: sandbox-ai's sandbox/mcp-signers")
    parser.add_argument("--record-review", nargs="+", metavar="NAME",
                        help="record the current shipped files of these reviewed servers in reviews.json")
    opts = parser.parse_args(argv)
    root = opts.root.resolve()
    files = [root / "catalog.json", root / "rootfs.json"]
    if opts.record_review:
        problems = record_review(root, opts.record_review)
        for problem in problems:
            print(f"refused: {problem}", file=sys.stderr)
        return 1 if problems else 0
    if opts.verify:
        if not opts.signers:
            parser.error("--verify needs --signers")
        results = [verify(path, opts.signers) for path in files]  # each file reported, not only the first bad one
        return 0 if all(results) else 1
    if not (opts.key and opts.reports):
        parser.error("--key and --reports are needed")
    missing = [path.name for path in files if not path.is_file()]
    if missing:
        print(f"refused: {', '.join(missing)} missing under {root}", file=sys.stderr)
        return 1
    problems = problems_of(root, opts.reports)
    for problem in problems:
        print(f"refused: {problem}", file=sys.stderr)
    if problems:
        print("nothing signed", file=sys.stderr)
        return 1
    catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
    pending = [e["name"] for e in catalog.get("entries", []) if not e.get("digest")]
    if pending:
        print(f"note: pending, not vouched for (sandbox-ai and axross refuse them): {', '.join(pending)}")
    for path in files:
        print(f"signed {sign(path, opts.key).name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
