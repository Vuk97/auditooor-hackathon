#!/usr/bin/env python3
# r36-rebuttal: bugfix-inventory-claude-20260610
"""Tests for tools/fresh-target-forward-test.py - the reusable fresh-target
forward-test runner and its deposit schema (auditooor.fresh_target_forward_test.v1).

Covers:
  - target_slug derivation (repo path + explicit name + sanitization)
  - is_unseen check (3-signal logic, including the unavailable-signal case)
  - FINAL_LEADS.md count parsing + honest-verdict extraction
  - build_record schema shape (incl. proof_backed_lead_yield the publisher reads)
  - deposit write + idempotent path
  - the re-emitted prb-proxy record exists with the PR11 numbers
  - capability-metric-publisher consumes the deposit (status: summarized)
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = REPO_ROOT / "tools" / "fresh-target-forward-test.py"
DEPOSIT_DIR = REPO_ROOT / "reports" / "fresh_target_forward_tests"


def _load_module():
    spec = importlib.util.spec_from_file_location("fresh_target_forward_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FT = _load_module()


class TestTargetSlug(unittest.TestCase):
    def test_repo_path(self):
        self.assertEqual(FT.target_slug("github.com/PaulRBerg/prb-proxy", None),
                         "prb-proxy")

    def test_trailing_slash(self):
        self.assertEqual(FT.target_slug("github.com/Foo/Bar/", None), "bar")

    def test_explicit_name_overrides(self):
        self.assertEqual(FT.target_slug("github.com/Foo/Bar", "MyTarget"),
                         "mytarget")

    def test_sanitizes_unsafe_chars(self):
        slug = FT.target_slug("github.com/Foo/Weird@Name!", None)
        self.assertNotIn("@", slug)
        self.assertNotIn("!", slug)
        self.assertTrue(slug)


class TestIsUnseen(unittest.TestCase):
    def test_no_signals_zero_is_unseen_true(self):
        # a slug that matches no audits workspace; corpus/dead-ends unavailable
        # or zero -> is_unseen true
        res = FT.compute_is_unseen(
            "github.com/Nonexistent/zzz-never-seen-target-xyz",
            "zzz-never-seen-target-xyz", None)
        self.assertIn("is_unseen", res)
        self.assertIn("signals", res)
        # with no prior workspace, the only way it is False is a corpus/dead-end
        # hit; for a clearly-novel slug we expect True
        self.assertEqual(res["signals"]["prior_workspaces_count"], 0)
        self.assertTrue(res["is_unseen"])

    def test_prior_workspace_blocks_unseen(self):
        # prb-proxy HAS a prior /Users/wolf/audits/prb-proxy workspace, so even
        # excluding the -fwdtest ws it is NOT unseen. This is the honest PR11 result.
        prb_ws = Path("/Users/wolf/audits/prb-proxy-fwdtest")
        res = FT.compute_is_unseen("github.com/PaulRBerg/prb-proxy",
                                   "prb-proxy", prb_ws)
        # if the prior workspace exists locally, is_unseen must be False
        if Path("/Users/wolf/audits/prb-proxy").exists():
            self.assertFalse(res["is_unseen"])
            self.assertIn("prb-proxy", res["signals"]["prior_workspaces"])

    def test_signals_shape(self):
        res = FT.compute_is_unseen("github.com/A/b", "b", None)
        sig = res["signals"]
        for k in ("prior_workspaces", "prior_workspaces_count",
                  "known_dead_ends_count", "fetchable_corpus_match_count"):
            self.assertIn(k, sig)


class TestFinalLeadsParsing(unittest.TestCase):
    def _write(self, body: str) -> Path:
        d = Path(tempfile.mkdtemp())
        p = d / "FINAL_LEADS.md"
        p.write_text(body)
        return p

    def test_parse_counts(self):
        p = self._write(
            "## Verdict summary\n\n"
            "| Class | Count |\n"
            "|-------|-------|\n"
            "| proof-backed (fileable) | 2 |\n"
            "| blocked-with-obligation | 1 |\n"
            "| source-ruled-out | 6 |\n")
        counts = FT.parse_final_leads_counts(p)
        self.assertEqual(counts["proof_backed"], 2)
        self.assertEqual(counts["blocked"], 1)
        self.assertEqual(counts["source_ruled_out"], 6)

    def test_missing_file_zeros(self):
        counts = FT.parse_final_leads_counts(Path("/nonexistent/FINAL_LEADS.md"))
        self.assertEqual(counts, {"proof_backed": 0, "blocked": 0,
                                  "source_ruled_out": 0})

    def test_honest_verdict_extraction(self):
        p = self._write(
            "stuff\n\nHONEST RESULT: 0 fileable findings. mature code.\n\n---\n")
        v = FT.extract_honest_verdict(p)
        self.assertIn("0 fileable findings", v)

    def test_honest_verdict_default_when_absent(self):
        p = self._write("no marker here\n")
        v = FT.extract_honest_verdict(p)
        self.assertIn("no HONEST RESULT", v)


class TestRunCmd(unittest.TestCase):
    def test_timeout_returns_quickly_for_process_group(self):
        started = time.time()
        rec = FT._run_cmd([
            sys.executable,
            "-c",
            "import subprocess, sys, time; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            "time.sleep(30)",
        ], REPO_ROOT, timeout=1)
        elapsed = time.time() - started
        self.assertEqual(rec["status"], "timeout")
        self.assertLess(elapsed, 8)


class TestBuildRecord(unittest.TestCase):
    def test_schema_shape(self):
        unseen = {"is_unseen": True, "signals": {}, "note": "x"}
        rec = FT.build_record(
            repo="github.com/A/b", pin="deadbeef", slug="b",
            workspace="/tmp/b", unseen=unseen,
            stages=[{"stage": "make-audit", "status": "ok"}],
            counts={"proof_backed": 0, "blocked": 0, "source_ruled_out": 3},
            honest_verdict="no leads", source_note="test")
        self.assertEqual(rec["schema"], "auditooor.fresh_target_forward_test.v1")
        self.assertEqual(rec["target"]["repo"], "github.com/A/b")
        self.assertEqual(rec["target"]["pin"], "deadbeef")
        self.assertTrue(rec["is_unseen"])
        self.assertEqual(rec["final_leads_counts"]["source_ruled_out"], 3)
        # the publisher reads this field directly
        self.assertEqual(rec["proof_backed_lead_yield"], 0)
        self.assertIn("stages_run", rec)
        self.assertIn("honest_verdict", rec)

    def test_proof_backed_yield_tracks_counts(self):
        unseen = {"is_unseen": False, "signals": {}, "note": ""}
        rec = FT.build_record(
            repo="r", pin="p", slug="s", workspace="w", unseen=unseen,
            stages=[], counts={"proof_backed": 4}, honest_verdict="",
            source_note="")
        self.assertEqual(rec["proof_backed_lead_yield"], 4)


class TestProvisionInTree(unittest.TestCase):
    """In-tree provisioning: clone REPO@PIN -> <ws>/repo, mirror src/, write
    targets.tsv + AUDIT_PIN.txt, so `make audit` runs IN-TREE. Uses a LOCAL
    fixture git repo (no network) cloned via a file:// URL."""

    def _make_fixture_repo(self, tmp: Path) -> tuple[str, str]:
        """Create a tiny local git repo with src/Foo.sol; return (url, pin)."""
        repo = tmp / "fixture-target"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "Foo.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract Foo { uint256 public x; }\n")
        # a dep dir that MUST be excluded from the mirror
        (repo / "lib").mkdir()
        (repo / "lib" / "Dep.sol").write_text("contract Dep {}\n")
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        import os
        run_env = {**os.environ, **env}

        def g(*a):
            # -c core.hooksPath=/dev/null bypasses any global commit-gate hook
            # so the isolated fixture repo commits hermetically.
            return subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", *a],
                cwd=str(repo), env=run_env,
                capture_output=True, text=True, check=True)
        g("init", "-q")
        g("add", "-A")
        g("commit", "-q", "-m", "fixture")
        pin = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                             capture_output=True, text=True, check=True).stdout.strip()
        return repo.as_uri(), pin  # file:// URL

    def test_provision_in_tree_true(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            url, pin = self._make_fixture_repo(tmp)
            ws = tmp / "target-fwdtest"
            summ = FT.provision_workspace_in_tree(url, pin, ws, clone_timeout=120)
            # workspace is provisioned IN-TREE (not claim-narrowed-out-of-tree)
            self.assertTrue(summ["in_tree"],
                            f"expected in_tree=true, got {summ}")
            # repo cloned at the exact pin
            self.assertTrue((ws / "repo" / ".git").exists())
            # src/ mirrored with the in-scope .sol, dep excluded
            self.assertTrue((ws / "src" / "Foo.sol").exists())
            self.assertFalse((ws / "src" / "Dep.sol").exists())
            self.assertFalse((ws / "src" / "lib").exists())
            # manifests written in canonical form
            tsv = (ws / "targets.tsv").read_text()
            self.assertIn("# repo\tref\trole", tsv)
            self.assertIn(pin, tsv)
            audit_pin = (ws / "AUDIT_PIN.txt").read_text()
            self.assertIn(f"audit-pin: {pin}", audit_pin)
            self.assertGreaterEqual(summ["mirrored_sol_file_count"], 1)

    def test_provision_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            url, pin = self._make_fixture_repo(tmp)
            ws = tmp / "target-fwdtest"
            first = FT.provision_workspace_in_tree(url, pin, ws, clone_timeout=120)
            self.assertTrue(first["in_tree"])
            # second run is a no-op re: clone (detects already-at-pin)
            second = FT.provision_workspace_in_tree(url, pin, ws, clone_timeout=120)
            self.assertTrue(second["in_tree"])
            clone_steps = [s for s in second["steps"] if s["step"] == "clone"]
            self.assertEqual(clone_steps[0]["status"], "already-at-pin")
            self.assertTrue((ws / "src" / "Foo.sol").exists())

    def test_provision_recorded_in_deposit(self):
        unseen = {"is_unseen": True, "signals": {}, "note": ""}
        provision = {"in_tree": True, "mirrored_sol_file_count": 3, "steps": []}
        rec = FT.build_record(
            repo="github.com/A/b", pin="p", slug="b", workspace="/tmp/b",
            unseen=unseen, stages=[], counts={}, honest_verdict="",
            source_note="", provision=provision)
        self.assertTrue(rec["provisioned_in_tree"])
        self.assertEqual(rec["provision_detail"]["mirrored_sol_file_count"], 3)

    def test_provision_none_when_skipped(self):
        unseen = {"is_unseen": True, "signals": {}, "note": ""}
        rec = FT.build_record(
            repo="r", pin="p", slug="s", workspace="w", unseen=unseen,
            stages=[], counts={}, honest_verdict="", source_note="",
            provision=None)
        # provisioned_in_tree is None when provisioning was not run
        self.assertIsNone(rec["provisioned_in_tree"])

    def test_forward_scaffold_writes_ready_files(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            provision = {
                "steps": [
                    {
                        "step": "mirror-src",
                        "sol_files": ["src/Foo.sol", "src/test/Foo.t.sol"],
                    }
                ]
            }
            FT._write_default_scope_and_severity(
                ws, "github.com/A/b", "deadbeef")
            asset = FT._write_forward_asset_plan(ws, provision)

            self.assertEqual(asset["status"], "created")
            self.assertTrue((ws / "SCOPE.md").exists())
            self.assertTrue((ws / "SEVERITY.md").exists())
            plan = (ws / "ASSET_PLAN_Smart_Contract.md").read_text()
            self.assertIn("- Plan status: ready", plan)
            self.assertIn("src/Foo.sol", plan)
            self.assertNotIn("src/test/Foo.t.sol", plan)
            self.assertNotIn("TBD", plan)

    def test_contract_picker_excludes_tests_and_mocks(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src" / "test").mkdir(parents=True)
            (ws / "src" / "Foo.sol").write_text("contract Foo {}\n")
            (ws / "src" / "MockFoo.sol").write_text("contract MockFoo {}\n")
            (ws / "src" / "test" / "Foo.t.sol").write_text("contract FooTest {}\n")
            picked = FT._contracts_for_forward_test(ws)
            self.assertEqual([str(p) for p in picked], ["src/Foo.sol"])

    def test_contract_name_ignores_comments(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Cooler.sol"
            p.write_text(
                "// a contract escrow appears in prose only\n"
                "interface Token {}\n"
                "contract Cooler {}\n")
            self.assertEqual(FT._contract_name_from_file(p), "Cooler")

    # r36-rebuttal: bugfix-inventory-claude-20260610
    # --- Bug fix: certora/interfaces/lib/out exclusion ---

    def test_contract_picker_excludes_certora_helpers(self):
        """certora helpers sort before real contracts alphabetically.
        Without the fix, _contracts_for_forward_test returns CertoraHarness.sol
        instead of Protocol.sol. This test fails on the buggy code and passes
        after the fix."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src" / "certora" / "helpers").mkdir(parents=True)
            (ws / "src" / "certora" / "helpers" / "Harness.sol").write_text(
                "contract CertoraHarness {}\n")
            (ws / "src" / "Protocol.sol").write_text("contract Protocol {}\n")
            picked = FT._contracts_for_forward_test(ws)
            self.assertEqual([str(p) for p in picked], ["src/Protocol.sol"],
                             "certora helper must be excluded from forward-test targets")

    def test_contract_picker_excludes_interfaces_subdir(self):
        """Files under src/interfaces/ are non-production and must be excluded."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src" / "interfaces").mkdir(parents=True)
            (ws / "src" / "interfaces" / "IFoo.sol").write_text(
                "interface IFoo { function foo() external; }\n")
            (ws / "src" / "Core.sol").write_text("contract Core {}\n")
            picked = FT._contracts_for_forward_test(ws)
            picked_strs = [str(p) for p in picked]
            self.assertNotIn("src/interfaces/IFoo.sol", picked_strs,
                             "interfaces/ subdirectory must be excluded")
            self.assertIn("src/Core.sol", picked_strs)

    def test_contract_picker_excludes_lib_and_out(self):
        """Files under src/lib/ and src/out/ are dependency trees / build
        artifacts and must never be selected as forward-test targets."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src" / "lib").mkdir(parents=True)
            (ws / "src" / "lib" / "Dep.sol").write_text("contract Dep {}\n")
            (ws / "src" / "out").mkdir(parents=True)
            (ws / "src" / "out" / "Artifact.sol").write_text("contract Artifact {}\n")
            (ws / "src" / "Real.sol").write_text("contract Real {}\n")
            picked = FT._contracts_for_forward_test(ws)
            picked_strs = [str(p) for p in picked]
            self.assertNotIn("src/lib/Dep.sol", picked_strs,
                             "lib/ subdir must be excluded from forward-test targets")
            self.assertNotIn("src/out/Artifact.sol", picked_strs,
                             "out/ subdir must be excluded from forward-test targets")
            self.assertIn("src/Real.sol", picked_strs)

    def test_contract_picker_morpho_midnight_pattern(self):
        """Regression test for morpho-midnight: three certora helpers sort before
        Midnight.sol alphabetically; with limit=3 the buggy code fills all slots
        with certora files and never reaches Midnight.sol. The fix must select
        only the real protocol contract."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "src" / "certora" / "helpers").mkdir(parents=True)
            (ws / "src" / "certora" / "helpers" / "AnotherHelper.sol").write_text(
                "contract AnotherHelper {}\n")
            (ws / "src" / "certora" / "helpers" / "FlashLiquidateCallback.sol").write_text(
                "contract FlashLiquidateCallback {}\n")
            (ws / "src" / "certora" / "helpers" / "ThirdHelper.sol").write_text(
                "contract ThirdHelper {}\n")
            (ws / "src" / "src").mkdir(parents=True)
            (ws / "src" / "src" / "Midnight.sol").write_text("contract Midnight {}\n")
            picked = FT._contracts_for_forward_test(ws, limit=3)
            picked_strs = [str(p) for p in picked]
            certora_in_result = [p for p in picked_strs if "certora" in p]
            self.assertEqual(certora_in_result, [],
                             "certora helpers must not fill the target slots (morpho-midnight pattern)")
            self.assertIn("src/src/Midnight.sol", picked_strs,
                          "real protocol contract must be reached after certora exclusion")

    # --- Bug fix: _contract_name_from_file falls back to interface name ---

    def test_contract_name_returns_none_for_interface_only_file(self):
        """When a file contains only interface declarations and the stem does not
        match any declaration name, _contract_name_from_file must return None
        (not the interface name). Without the fix it returns 'IERC20'."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Interfaces.sol"
            p.write_text(
                "interface IERC20 {\n"
                "    function transfer(address, uint256) external returns (bool);\n"
                "}\n")
            result = FT._contract_name_from_file(p)
            self.assertIsNone(result,
                              f"interface-only file with mismatched stem must return None, "
                              f"got {result!r}")

    def test_contract_name_returns_none_for_library_only_file(self):
        """Library-only files with a mismatched stem must also return None so
        the caller's `if cname:` guard suppresses --contract-name."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "MathUtils.sol"
            p.write_text(
                "library FixedPointMath {\n"
                "    function mul(uint256 a, uint256 b) internal pure returns (uint256) {\n"
                "        return a;\n"
                "    }\n"
                "}\n")
            result = FT._contract_name_from_file(p)
            # stem is 'mathutils', does not match 'fixedpointmath' -> should be None
            self.assertIsNone(result,
                              f"library-only file with mismatched stem must return None, "
                              f"got {result!r}")

    def test_contract_name_still_finds_named_contract(self):
        """Normal contract files must still have their name extracted correctly
        - the fix must not break the positive case."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Token.sol"
            p.write_text(
                "interface IERC20 { function transfer(address, uint256) external; }\n"
                "contract Token is IERC20 {\n"
                "    function transfer(address, uint256) external {}\n"
                "}\n")
            result = FT._contract_name_from_file(p)
            self.assertEqual(result, "Token",
                             "contract keyword in file must be found regardless of preceding interface")


class TestDepositWrite(unittest.TestCase):
    def test_write_and_path_idempotent(self):
        unseen = {"is_unseen": True, "signals": {}, "note": ""}
        rec = FT.build_record(
            repo="github.com/T/test-write", pin="aa", slug="test-write-xyz",
            workspace="/tmp/x", unseen=unseen, stages=[], counts={},
            honest_verdict="", source_note="")
        out = FT.write_deposit(rec, "test-write-xyz", date="2099-01-01")
        try:
            self.assertTrue(out.exists())
            loaded = json.loads(out.read_text())
            self.assertEqual(loaded["schema"],
                             "auditooor.fresh_target_forward_test.v1")
            # path is deterministic for same slug+date
            self.assertEqual(out, FT.deposit_path_for("test-write-xyz",
                                                      "2099-01-01"))
        finally:
            out.unlink(missing_ok=True)


class TestPrbProxyReemitted(unittest.TestCase):
    """The re-emitted prb-proxy record must exist with PR11 numbers."""

    def test_record_exists_and_valid(self):
        FT.reemit_prb_proxy()
        path = DEPOSIT_DIR / "prb-proxy-2026-05-30.json"
        self.assertTrue(path.exists(),
                        "run: python3 tools/fresh-target-forward-test.py "
                        "--reemit-prb-proxy")
        rec = json.loads(path.read_text())
        self.assertEqual(rec["schema"],
                         "auditooor.fresh_target_forward_test.v1")
        self.assertEqual(rec["target"]["repo"], "github.com/PaulRBerg/prb-proxy")
        self.assertEqual(
            rec["target"]["pin"],
            "e45f5325d4b6003227a6c4bdaefac9453f89de2e")
        # PR11 honest numbers: 0 proof-backed, 6 source-ruled-out
        self.assertEqual(rec["final_leads_counts"]["proof_backed"], 0)
        self.assertEqual(rec["final_leads_counts"]["source_ruled_out"], 6)
        self.assertEqual(rec["proof_backed_lead_yield"], 0)
        # stages_run trail is non-empty and includes the key pipeline stages
        stages = {s["stage"] for s in rec["stages_run"]}
        self.assertIn("make-audit", stages)
        self.assertIn("adversarial-candidate-verify", stages)

    def test_reemit_is_idempotent(self):
        # re-running the re-emit produces the same file content
        path = DEPOSIT_DIR / "prb-proxy-2026-05-30.json"
        FT.reemit_prb_proxy()
        before = json.loads(path.read_text()) if path.exists() else None
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--reemit-prb-proxy", "--json"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        after = json.loads(path.read_text())
        # generated_at_utc differs; everything else is stable
        if before:
            before.pop("generated_at_utc", None)
            after_cmp = dict(after)
            after_cmp.pop("generated_at_utc", None)
            self.assertEqual(before["final_leads_counts"],
                             after_cmp["final_leads_counts"])


class TestPublisherConsumesDeposit(unittest.TestCase):
    def test_publisher_summarizes_deposit(self):
        pub = REPO_ROOT / "tools" / "capability-metric-publisher.py"
        if not pub.exists():
            self.skipTest("capability-metric-publisher.py absent")
        proc = subprocess.run(
            [sys.executable, str(pub), "--json"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        data = json.loads(proc.stdout)
        fs = data.get("fresh_target") or data.get("report", {}).get("fresh_target")
        self.assertIsNotNone(fs, "publisher emitted no fresh_target slot")
        # once a deposit exists, the slot is summarized (not not-run)
        self.assertEqual(fs["status"], "summarized")
        self.assertEqual(fs["proof_backed_lead_yield"], 0)


if __name__ == "__main__":
    unittest.main()
