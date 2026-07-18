#!/usr/bin/env python3
"""Offline tests for tools/audit/intake-scaffolder.py (Wave-5 W5-H3).

All tests run in tempfile.TemporaryDirectory() sandboxes; nothing under
~/audits/ is touched. No network, no subprocess.

Test list:
  1.  test_scaffold_creates_six_intake_files
  2.  test_scaffold_creates_directory_layout
  3.  test_language_mix_detected_from_local_repo
  4.  test_file_inventory_in_intake_baseline
  5.  test_severity_template_per_platform
  6.  test_invalid_platform_rejected
  7.  test_invalid_slug_rejected
  8.  test_refuses_to_overwrite_existing_workspace
  9.  test_dry_run_writes_nothing
  10. test_scope_json_and_scope_md_share_source
  11. test_remote_url_mode_degrades_cleanly
  12. test_todo_human_blocks_present
  13. test_json_summary_shape
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit" / "intake-scaffolder.py"


def _load():
    spec = importlib.util.spec_from_file_location("intake_scaffolder", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scaffolder = _load()


def _call(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = scaffolder.main(argv)
    except SystemExit as exc:
        rc = int(exc.code or 0)
    return rc, out.getvalue(), err.getvalue()


def _make_fixture_repo(root: Path) -> Path:
    """Build a tiny multi-language fixture repo on disk."""
    repo = root / "fixture-repo"
    (repo / "src").mkdir(parents=True)
    (repo / "contracts").mkdir(parents=True)
    (repo / "node_modules" / "junk").mkdir(parents=True)
    (repo / "contracts" / "Vault.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "contract Vault {}\n"
    )
    (repo / "contracts" / "Token.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Token {}\n"
    )
    (repo / "src" / "keeper.go").write_text(
        "package keeper\nfunc Foo() {}\n"
    )
    (repo / "node_modules" / "junk" / "skip.sol").write_text("contract X {}\n")
    return repo


class TestIntakeScaffolder(unittest.TestCase):

    def test_scaffold_creates_six_intake_files(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            rc, out, err = _call([
                "--repo", str(repo), "--pin", "abc1234",
                "--platform", "cantina", "--audits-dir", str(Path(td) / "audits"),
            ])
            self.assertEqual(rc, 0, err)
            ws = Path(td) / "audits" / "fixture-repo"
            for f in ("SCOPE.md", "SEVERITY.md", "INTAKE_BASELINE.md",
                      "PRIOR_CONCERNS.md", "scope.json",
                      ".auditooor/workspace_lock.json"):
                self.assertTrue((ws / f).is_file(), f"missing {f}")

    def test_scaffold_creates_directory_layout(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            _call(["--repo", str(repo), "--pin", "abc1234",
                   "--platform", "immunefi", "--audits-dir", str(Path(td) / "audits")])
            ws = Path(td) / "audits" / "fixture-repo"
            for d in ("submissions/staging", "submissions/paste_ready",
                      "poc-tests", ".auditooor", "prior_audits"):
                self.assertTrue((ws / d).is_dir(), f"missing dir {d}")

    def test_language_mix_detected_from_local_repo(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            inv = scaffolder.inventory_repo(repo)
            self.assertTrue(inv["available"])
            self.assertEqual(inv["language_mix"].get("solidity"), 2)
            self.assertEqual(inv["language_mix"].get("go"), 1)
            # node_modules must be skipped
            self.assertEqual(inv["file_count"], 3)

    def test_file_inventory_in_intake_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            _call(["--repo", str(repo), "--pin", "deadbeef",
                   "--platform", "sherlock", "--audits-dir", str(Path(td) / "audits")])
            text = (Path(td) / "audits" / "fixture-repo" / "INTAKE_BASELINE.md").read_text()
            self.assertIn("contracts/Vault.sol", text)
            self.assertIn("src/keeper.go", text)
            self.assertNotIn("node_modules", text)

    def test_severity_template_per_platform(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            for plat, marker in (
                ("cantina", "Cantina program rubric"),
                ("immunefi", "Primacy-of-Impact"),
                ("sherlock", "no Critical/Low tier"),
                ("code4rena", "Code4rena"),
                ("hats", "Hats vault committee"),
                ("other", "no known platform template"),
            ):
                ws_name = f"plat-{plat}"
                _call(["--repo", str(repo), "--pin", "abc",
                       "--platform", plat, "--name", ws_name,
                       "--audits-dir", str(Path(td) / "audits")])
                sev = (Path(td) / "audits" / ws_name / "SEVERITY.md").read_text()
                self.assertIn(marker, sev, f"{plat} template wrong")

    def test_invalid_platform_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            rc, out, err = _call(["--repo", str(repo), "--pin", "abc",
                                   "--platform", "bogus", "--audits-dir", str(Path(td) / "audits")])
            self.assertEqual(rc, 2)
            self.assertIn("unknown platform", err)

    def test_invalid_slug_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            rc, out, err = _call(["--repo", str(repo), "--pin", "abc",
                                   "--platform", "cantina",
                                   "--name", "Bad Slug!", "--audits-dir", str(Path(td) / "audits")])
            self.assertEqual(rc, 2)
            self.assertIn("invalid slug", err)

    def test_refuses_to_overwrite_existing_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            argv = ["--repo", str(repo), "--pin", "abc",
                    "--platform", "cantina", "--audits-dir", str(Path(td) / "audits")]
            rc1, _, _ = _call(argv)
            self.assertEqual(rc1, 0)
            rc2, out, err = _call(argv)
            self.assertEqual(rc2, 2)
            self.assertIn("already exists", err)

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            rc, out, err = _call(["--repo", str(repo), "--pin", "abc",
                                   "--platform", "cantina",
                                   "--audits-dir", str(Path(td) / "audits"), "--dry-run"])
            self.assertEqual(rc, 0, err)
            self.assertFalse((Path(td) / "audits" / "fixture-repo").exists())
            self.assertIn("dry-run", out)

    def test_scope_json_and_scope_md_share_source(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            _call(["--repo", str(repo), "--pin", "pinSHA99",
                   "--platform", "cantina", "--audits-dir", str(Path(td) / "audits")])
            ws = Path(td) / "audits" / "fixture-repo"
            scope_json = json.loads((ws / "scope.json").read_text())
            scope_md = (ws / "SCOPE.md").read_text()
            self.assertEqual(scope_json["audit_pin_sha"], "pinSHA99")
            self.assertIn("pinSHA99", scope_md)
            self.assertEqual(scope_json["language_mix"].get("solidity"), 2)
            self.assertIn("mirrors scope.json", scope_md)

    def test_remote_url_mode_degrades_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            rc, out, err = _call([
                "--repo", "https://github.com/example/proto.git",
                "--pin", "v1.2.3", "--platform", "immunefi",
                "--audits-dir", str(Path(td) / "audits"), "--json",
            ])
            self.assertEqual(rc, 0, err)
            summary = json.loads(out)
            self.assertFalse(summary["inventory_available"])
            self.assertEqual(summary["file_count"], 0)
            self.assertEqual(summary["target_repo"], "example/proto")
            self.assertEqual(summary["slug"], "proto")

    def test_todo_human_blocks_present(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            _call(["--repo", str(repo), "--pin", "abc",
                   "--platform", "cantina", "--audits-dir", str(Path(td) / "audits")])
            ws = Path(td) / "audits" / "fixture-repo"
            for f in ("SCOPE.md", "SEVERITY.md", "INTAKE_BASELINE.md",
                      "PRIOR_CONCERNS.md"):
                self.assertIn("TODO(human)", (ws / f).read_text(),
                              f"{f} missing TODO(human) markers")

    def test_json_summary_shape(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _make_fixture_repo(Path(td))
            rc, out, err = _call(["--repo", str(repo), "--pin", "abc",
                                   "--platform", "cantina",
                                   "--audits-dir", str(Path(td) / "audits"), "--json"])
            self.assertEqual(rc, 0, err)
            summary = json.loads(out)
            self.assertEqual(summary["schema"],
                             "auditooor.intake_scaffolder.v1")
            self.assertEqual(len(summary["intake_files"]), 6)
            self.assertIn("written", summary)
            self.assertEqual(len(summary["written"]), 6)


if __name__ == "__main__":
    unittest.main()
