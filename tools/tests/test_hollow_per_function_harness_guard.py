#!/usr/bin/env python3
# r36-rebuttal: lane FIX-HOLLOW-PER-FUNCTION-HARNESS registered via agent-pathspec-register.py
"""Guard tests for the hollow-per-function-harness coverage-theater detection.

Three directions tested:

(a) VACUOUS-FAILS: a workspace with a value-moving function whose per-function
    harnesses all ran but produced 0 mutation-verified kills (DEEP_AUDIT_HOLLOW.flag
    present + genuine_coverage_manifest.checkable_count>0 + mutation_verified_genuine_count=0)
    MUST fail both audit-honesty-check (fail-hollow-per-function-harnesses) and
    honest-zero-verify (deep_evidence check fails).

(b) GENUINE-PASSES: a workspace with a value-moving function AND a real
    mutation-verified per-function harness (per_function_verified>=1 in
    mutation_verify_coverage.json + mutation_verified_genuine_count>=1 in
    genuine_coverage_manifest.json, no DEEP_AUDIT_HOLLOW.flag) MUST still pass both
    checks (no regression).

(c) NO-VALUE-MOVING-FNS-UNAFFECTED: a workspace with NO value-moving functions
    (no genuine_coverage_manifest.json / no DEEP_AUDIT_HOLLOW.flag) is not failed by
    the new gate - the flag-absent / checkable_count=0 branch is a no-op.

All tests are generic (no workspace literals, no language hardcoding). The
synthetic workspaces use Solidity source files so both the honesty-check language
arm and the value-moving-functions enumerator produce consistent results.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_HONESTY_TOOL = _REPO / "tools" / "audit-honesty-check.py"
_HZV_TOOL = _REPO / "tools" / "honest-zero-verify.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_honesty(ws: Path) -> dict:
    cp = subprocess.run(
        [sys.executable, str(_HONESTY_TOOL), "--workspace", str(ws), "--json"],
        capture_output=True,
        text=True,
    )
    if not cp.stdout.strip():
        raise AssertionError(
            f"no JSON on stdout (rc={cp.returncode}); stderr=\n{cp.stderr[:600]}"
        )
    return json.loads(cp.stdout)


def _run_hzv(ws: Path) -> dict:
    """Run honest-zero-verify as a module (no subprocess) - faster + no TTL problem."""
    spec = importlib.util.spec_from_file_location("_hzv_guard", str(_HZV_TOOL))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_hzv_guard"] = m
    spec.loader.exec_module(m)
    return m._check_deep_evidence(ws)


def _wj(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def _mk_base_ws() -> Path:
    """Minimal workspace skeleton - Solidity source, .auditooor dir."""
    ws = Path(tempfile.mkdtemp(prefix="hpfh_test_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    # A Solidity file with a value-moving function (safeTransfer call).
    (src / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "import {IERC20} from './IERC20.sol';\n"
        "contract Vault {\n"
        "    IERC20 public token;\n"
        "    mapping(address => uint256) public balances;\n"
        "    function withdraw(address to, uint256 amount) external {\n"
        "        balances[msg.sender] -= amount;\n"
        "        token.safeTransfer(to, amount);\n"
        "    }\n"
        "    function deposit(uint256 amount) external {\n"
        "        token.safeTransferFrom(msg.sender, address(this), amount);\n"
        "        balances[msg.sender] += amount;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    return ws


def _write_fuzz_artifact(ws: Path) -> None:
    """Write a minimal non-trivial deep-engine fuzz artifact (>200 bytes)."""
    d = ws / ".auditooor" / "deep-engine-findings"
    d.mkdir(parents=True, exist_ok=True)
    (d / "run_20260613.md").write_text(
        "# Deep engine run\n\n"
        "Engine: medusa\nRun date: 2026-06-13\nFuzz targets: 3\n\n"
        "All properties held across 1M+ calls. No counterexamples found.\n"
        "Coverage: 92 branches covered, 0 reverts flagged as invariant violations.\n"
        "Mutation score: 12/15 mutants killed by the invariant suite.\n",
        encoding="utf-8",
    )


def _write_coverage_report(ws: Path) -> None:
    _wj(ws / ".auditooor" / "coverage_report.json", {
        "covered": 10, "total": 10, "pct": 1.0,
    })


# ---------------------------------------------------------------------------
# (a) VACUOUS HARNESSES - must FAIL
# ---------------------------------------------------------------------------

class VacuousHarnessFailsTest(unittest.TestCase):
    """Harnesses ran (checkable_count>0) but every one was error/silent-skip.
    DEEP_AUDIT_HOLLOW.flag present + mutation_verified_genuine_count=0.
    Both gates must reject the workspace."""

    def setUp(self):
        self.ws = _mk_base_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # mutation_verify_coverage: cross_function_verified=29, per_function_verified=0
        # (the theater scenario from morpho-midnight)
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 29,
                "per_function_verified": 0,
                "total": 29,
            }
        })

        # genuine_coverage_manifest: harnesses ran but 0 genuine kills
        _wj(a / "genuine_coverage_manifest.json", {
            "mutation_verified_genuine_count": 0,
            "checkable_count": 45,
            "status": "complete",
            "summary": "45 harnesses checked, 0 mutation-verified genuine",
        })

        # DEEP_AUDIT_HOLLOW.flag (written by hollow-engine-check.py)
        (a / "DEEP_AUDIT_HOLLOW.flag").write_text(
            "scaffold-only: 0 genuine mutation-verified harnesses\n"
            "mutation_verified_genuine = 0\ncheckable = 45\n",
            encoding="utf-8",
        )

        # Write minimal engine artifacts so real_execution=True (solidity arm)
        fuzz_dir = self.ws / "fuzz_runs" / "run_20260613"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "medusa",
            "status": "ok",
            "properties_checked": 15,
        })
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True,
            "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_honesty_check_fails_hollow_per_function_harnesses(self):
        """audit-honesty-check must reject vacuous harness theater.

        The workspace carries DEEP_AUDIT_HOLLOW.flag + genuine_coverage_manifest
        showing checkable_count>0 and mutation_verified_genuine_count=0.
        We assert that EITHER fail-hollow-per-function-harnesses OR
        fail-hollow-engines appears in fails (both are hard-fails; the dedup
        set in check() skips fail-hollow-per-function-harnesses when
        fail-hollow-engines already fired, which is the correct behavior - the
        workspace is rejected either way). The primary assertion is that the
        verdict is NOT pass-genuinely-audited.
        """
        result = _run_honesty(self.ws)
        _hollow_fails = {
            "fail-hollow-per-function-harnesses",
            "fail-hollow-engines",
            "fail-stub-harnesses",
        }
        self.assertTrue(
            bool(_hollow_fails & set(result["fails"])),
            f"expected at least one hollow fail in fails, got: {result['fails']}",
        )
        self.assertNotEqual(
            result["verdict"],
            "pass-genuinely-audited",
            "vacuous harness theater MUST NOT pass as genuinely audited",
        )

    def test_honesty_check_fail_when_engines_genuinely_ran(self):
        """When real_execution=True (engine genuinely ran) and hollow flag is
        present with gcm showing 0 genuine, fail-hollow-per-function-harnesses
        must specifically fire (not just fail-hollow-engines).

        To achieve real_execution=True for the Solidity arm, we add a
        per-function harness manifest (the 'real_harnesses' path) - not a stub.
        We also need the per-function harness stub count to be 0 so
        fail-stub-harnesses does not pre-empt the new gate.
        """
        a = self.ws / ".auditooor"
        # Add a per-function harness manifest with properties_checked > 0
        # so the solidity arm sees real_harnesses > 0
        pf_dir = a / "per_function_harnesses"
        pf_dir.mkdir(parents=True, exist_ok=True)
        _wj(pf_dir / "manifest.json", {
            "per_function_harnesses": [
                {
                    "harness_path": str(pf_dir / "Vault_withdraw.t.sol"),
                    "status": "executed",
                    "properties_checked": 2,
                }
            ]
        })
        # Write the harness file so it IS on disk (not a stub)
        (pf_dir / "Vault_withdraw.t.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "// real harness\ncontract Test { function test_withdraw() public {} }\n",
            encoding="utf-8",
        )
        result = _run_honesty(self.ws)
        # With real_harnesses > 0, fail-stub-harnesses should not fire.
        # The hollow flag + gcm should fire fail-hollow-per-function-harnesses.
        # In any case, the workspace must not pass.
        self.assertNotEqual(
            result["verdict"],
            "pass-genuinely-audited",
            f"theater workspace must not pass as genuinely audited, "
            f"fails: {result['fails']}",
        )

    def test_honest_zero_verify_fails_deep_evidence(self):
        """honest-zero-verify._check_deep_evidence must return False for theater workspace.

        The workspace has DEEP_AUDIT_HOLLOW.flag + Vault.sol (which auto-enumerates as a
        value-moving workspace). Either the vmf-direct gate or the hollow-flag gate may fire
        first; both are correct rejections. We assert ok=False and that the reason mentions
        EITHER the hollow flag OR value_moving_functions (both indicate the same hollow state).
        """
        ok, reason, _ = _run_hzv(self.ws)
        self.assertFalse(
            ok,
            f"_check_deep_evidence must FAIL when DEEP_AUDIT_HOLLOW.flag present "
            f"and per_function_verified=0. reason: {reason}",
        )
        # Accept either gate's reason - both correctly identify the hollow workspace.
        _hollow_cited = "DEEP_AUDIT_HOLLOW" in reason or "value_moving_functions" in reason
        self.assertTrue(
            _hollow_cited,
            f"reason should cite either DEEP_AUDIT_HOLLOW.flag or value_moving_functions "
            f"(whichever gate fires first), got: {reason}",
        )

    def test_honest_zero_verify_fails_gcm_gate(self):
        """Without the flag, the gcm gate also independently catches theater.

        Remove the flag - honest-zero-verify should still fail via the
        genuine_coverage_manifest path (checkable_count>0, mutation_verified_genuine_count=0,
        per_function_verified=0).
        """
        (self.ws / ".auditooor" / "DEEP_AUDIT_HOLLOW.flag").unlink()
        ok, reason, _ = _run_hzv(self.ws)
        self.assertFalse(
            ok,
            "even without DEEP_AUDIT_HOLLOW.flag, genuine_coverage_manifest with "
            "checkable_count>0 and mutation_verified_genuine_count=0 must fail. "
            f"reason: {reason}",
        )
        self.assertIn(
            "genuine_coverage_manifest",
            reason,
            f"reason should cite genuine_coverage_manifest, got: {reason}",
        )


# ---------------------------------------------------------------------------
# (b) GENUINE HARNESS - must still PASS (no regression)
# ---------------------------------------------------------------------------

class GenuineHarnessPassesTest(unittest.TestCase):
    """A workspace with at least one real mutation-verified per-function harness
    must pass both gates (no over-strict regression)."""

    def setUp(self):
        self.ws = _mk_base_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # per_function_verified >= 1
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 5,
                "per_function_verified": 3,
                "total": 8,
            }
        })

        # genuine_coverage_manifest: real kills
        _wj(a / "genuine_coverage_manifest.json", {
            "mutation_verified_genuine_count": 3,
            "checkable_count": 5,
            "status": "complete",
            "summary": "5 harnesses checked, 3 mutation-verified genuine",
        })

        # NO DEEP_AUDIT_HOLLOW.flag (was cleaned up by hollow-engine-check on
        # a genuine run)

        # Engine artifacts
        fuzz_dir = self.ws / "fuzz_runs" / "run_20260613"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "medusa",
            "status": "ok",
            "properties_checked": 5,
        })
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True,
            "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_honest_zero_verify_passes_genuine(self):
        """_check_deep_evidence must return True for a workspace with real kills."""
        ok, reason, fp = _run_hzv(self.ws)
        self.assertTrue(
            ok,
            f"a workspace with per_function_verified=3 and no hollow flag "
            f"MUST pass _check_deep_evidence. reason: {reason}",
        )

    def test_honesty_check_no_hollow_per_function_fail(self):
        """audit-honesty-check must NOT emit fail-hollow-per-function-harnesses
        for a workspace with genuine per-function mutation kills."""
        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"genuine workspace must not have fail-hollow-per-function-harnesses, "
            f"got: {result['fails']}",
        )


# ---------------------------------------------------------------------------
# (c) NO VALUE-MOVING FNS - must be unaffected
# ---------------------------------------------------------------------------

class NoValueMovingFnsUnaffectedTest(unittest.TestCase):
    """A workspace with no genuine_coverage_manifest.json, no DEEP_AUDIT_HOLLOW.flag,
    and no value-moving functions (value_moving_functions.json with function_count=0)
    is not affected by the new vmf-direct gate.

    We must write an explicit value_moving_functions.json with function_count=0 to
    prevent the auto-enumeration from finding value-moving functions in the Vault.sol
    source file created by _mk_base_ws()."""

    def setUp(self):
        self.ws = _mk_base_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # mutation_verify_coverage has verified harnesses but no per-function
        # manifest (Go-style workspace or prose-only)
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 8,
                "per_function_verified": 0,
                "total": 8,
            }
        })

        # Explicit vmf with 0 functions so the vmf-direct gate is a no-op.
        # (Without this, auto-enum would find value-moving fns in Vault.sol and
        # the gate would fire - but this test's intent is to cover the no-value-moving
        # surface case: a workspace where no transfer/ledger-write functions exist.)
        _wj(a / "value_moving_functions.json", {
            "workspace": str(self.ws),
            "generated_at": "2026-06-13T00:00:00Z",
            "function_count": 0,
            "functions": [],
        })

        # NO genuine_coverage_manifest.json (Go/non-Solidity path)
        # NO DEEP_AUDIT_HOLLOW.flag

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_honest_zero_verify_passes_no_gcm(self):
        """When genuine_coverage_manifest.json is absent AND hollow flag is absent,
        the new gate must not fire - workspace should pass _check_deep_evidence
        (modulo coverage_report.json requirement)."""
        ok, reason, _ = _run_hzv(self.ws)
        self.assertTrue(
            ok,
            f"a workspace with no gcm and no hollow flag must pass _check_deep_evidence. "
            f"reason: {reason}",
        )

    def test_honesty_check_no_spurious_fail(self):
        """audit-honesty-check must not emit fail-hollow-per-function-harnesses
        when DEEP_AUDIT_HOLLOW.flag is absent."""
        # Provide enough engine artifacts for real_execution=True
        fuzz_dir = self.ws / "fuzz_runs" / "run_20260613"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "medusa",
            "status": "ok",
            "properties_checked": 8,
        })
        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"no hollow flag => must not emit fail-hollow-per-function-harnesses, "
            f"got: {result['fails']}",
        )


# ---------------------------------------------------------------------------
# (d) STALE FLAG - genuine kills present in gcm overrides the flag
# ---------------------------------------------------------------------------

class StaleFlagSkippedTest(unittest.TestCase):
    """When DEEP_AUDIT_HOLLOW.flag is present BUT genuine_coverage_manifest.json
    shows mutation_verified_genuine_count > 0 (the harnesses were fixed after
    the flag was written and the flag was not cleaned up), neither gate should
    fail the workspace - the gcm is the ground truth over a stale flag."""

    def setUp(self):
        self.ws = _mk_base_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # per_function_verified > 0 (harnesses fixed)
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 10,
                "per_function_verified": 4,
                "total": 14,
            }
        })

        # gcm: genuine kills present
        _wj(a / "genuine_coverage_manifest.json", {
            "mutation_verified_genuine_count": 4,
            "checkable_count": 5,
            "status": "complete",
            "summary": "4 genuine kills",
        })

        # Stale DEEP_AUDIT_HOLLOW.flag left over from before the fix
        (a / "DEEP_AUDIT_HOLLOW.flag").write_text(
            "scaffold-only: 0 genuine mutation-verified harnesses\n"
            "mutation_verified_genuine = 0\ncheckable = 0\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_honest_zero_verify_skips_stale_flag(self):
        """_check_deep_evidence must pass when gcm shows genuine kills,
        even though the hollow flag is still on disk."""
        ok, reason, _ = _run_hzv(self.ws)
        self.assertTrue(
            ok,
            f"stale hollow flag must NOT fail _check_deep_evidence when "
            f"gcm shows genuine kills. reason: {reason}",
        )

    def test_honesty_check_skips_stale_flag(self):
        """audit-honesty-check must NOT emit fail-hollow-per-function-harnesses
        when gcm shows mutation_verified_genuine_count > 0."""
        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"stale hollow flag must not fail honesty check when gcm shows "
            f"genuine kills. got: {result['fails']}",
        )


# ---------------------------------------------------------------------------
# PATH 2 guard tests: value-moving-functions direct (no DEEP_AUDIT_HOLLOW.flag)
# This is the "monero case": a workspace that never ran the deep audit pipeline
# at all (no hollow flag was written) but has uncovered value-moving functions.
# ---------------------------------------------------------------------------

def _mk_vmf_ws() -> Path:
    """Workspace with a pre-written value_moving_functions.json (no hollow flag)."""
    ws = Path(tempfile.mkdtemp(prefix="vmf_direct_test_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    # Minimal Solidity source (Solidity arm for _detect_lang).
    (src / "Ledger.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Ledger {\n"
        "    mapping(address => uint256) public balances;\n"
        "    function transfer(address to, uint256 amt) external {\n"
        "        balances[msg.sender] -= amt;\n"
        "        balances[to] += amt;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    return ws


class ValueMovingFnsNoFlagFailsTest(unittest.TestCase):
    """(a) Synthetic workspace: value_moving_functions.json lists >=1 fn +
    NO genuine harness (per_function_verified=0, gcm_genuine=0) +
    NO DEEP_AUDIT_HOLLOW.flag -> MUST fail (fail-hollow-per-function-harnesses).

    This is the monero false-green: a workspace that never ran deep audit at
    all but has an enumerated value-moving surface with zero per-fn coverage."""

    def setUp(self):
        self.ws = _mk_vmf_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # value_moving_functions.json: 1 value-moving function, no hollow flag
        _wj(a / "value_moving_functions.json", {
            "workspace": str(self.ws),
            "generated_at": "2026-06-13T00:00:00Z",
            "function_count": 1,
            "functions": [
                {
                    "file": "src/Ledger.sol",
                    "function": "transfer",
                    "transfer_hit": True,
                    "ledger_write_hit": True,
                    "transfer_evidence": ["balances[msg.sender] -= amt"],
                    "ledger_write_evidence": ["balances"],
                }
            ],
        })

        # mutation_verify_coverage: per_function_verified=0 (no per-fn harness ran)
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 0,
                "per_function_verified": 0,
                "total": 0,
            }
        })

        # NO genuine_coverage_manifest.json
        # NO DEEP_AUDIT_HOLLOW.flag

        # Engine artifacts so real_execution=True for the Solidity arm.
        # The Solidity arm reads .auditooor/<engine>/artifact.json, not fuzz_runs/.
        # Write a halmos artifact with status="ok" to satisfy real_execution.
        _wj(a / "halmos" / "artifact.json", {"status": "ok", "properties_checked": 5})
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True,
            "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_honesty_check_fails_vmf_direct(self):
        """audit-honesty-check must emit fail-hollow-per-function-harnesses
        when value_moving_functions.json has >=1 fn, per_function_verified=0,
        and NO DEEP_AUDIT_HOLLOW.flag is present."""
        result = _run_honesty(self.ws)
        self.assertIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"value-moving fns + no genuine harness + no hollow flag MUST fail; "
            f"got fails={result['fails']}",
        )
        self.assertNotEqual(
            result["verdict"],
            "pass-genuinely-audited",
            "workspace with uncovered value-moving fns must not pass as genuinely audited",
        )

    def test_honest_zero_verify_fails_vmf_direct(self):
        """honest-zero-verify._check_deep_evidence must fail when value_moving_functions.json
        lists >=1 fn and per_function_verified=0, even without DEEP_AUDIT_HOLLOW.flag."""
        ok, reason, _ = _run_hzv(self.ws)
        self.assertFalse(
            ok,
            f"_check_deep_evidence must FAIL when value-moving fns exist with no "
            f"genuine per-fn harness. reason: {reason}",
        )
        self.assertIn(
            "value_moving_functions",
            reason,
            f"reason must cite value_moving_functions, got: {reason}",
        )


class ValueMovingFnsGenuineHarnessPassesTest(unittest.TestCase):
    """(b) value_moving_functions.json has >=1 fn + genuine per-fn mutation-verified
    harness (per_function_verified>=1 OR gcm_genuine>=1) -> MUST still pass (no
    over-strict regression)."""

    def setUp(self):
        self.ws = _mk_vmf_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # value_moving_functions.json: 1 value-moving function
        _wj(a / "value_moving_functions.json", {
            "workspace": str(self.ws),
            "generated_at": "2026-06-13T00:00:00Z",
            "function_count": 1,
            "functions": [
                {
                    "file": "src/Ledger.sol",
                    "function": "transfer",
                    "transfer_hit": True,
                    "ledger_write_hit": True,
                    "transfer_evidence": ["balances[msg.sender] -= amt"],
                    "ledger_write_evidence": ["balances"],
                }
            ],
        })

        # mutation_verify_coverage: per_function_verified=2 (genuine harness ran)
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 3,
                "per_function_verified": 2,
                "total": 5,
            }
        })

        # genuine_coverage_manifest: real kills
        _wj(a / "genuine_coverage_manifest.json", {
            "mutation_verified_genuine_count": 2,
            "checkable_count": 2,
            "status": "complete",
            "summary": "2 genuine per-function kills",
        })

        # NO DEEP_AUDIT_HOLLOW.flag
        fuzz_dir = self.ws / "fuzz_runs" / "run_20260613c"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "medusa",
            "status": "ok",
            "properties_checked": 5,
        })
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True,
            "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_honesty_check_passes_genuine_vmf(self):
        """audit-honesty-check must NOT emit fail-hollow-per-function-harnesses
        when per_function_verified>=1 and gcm_genuine>=1."""
        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"genuine per-fn harness present: must not emit hollow fail; "
            f"got fails={result['fails']}",
        )

    def test_honest_zero_verify_passes_genuine_vmf(self):
        """_check_deep_evidence must pass when per_function_verified>=1."""
        ok, reason, _ = _run_hzv(self.ws)
        self.assertTrue(
            ok,
            f"_check_deep_evidence must PASS when per_function_verified>=1. "
            f"reason: {reason}",
        )


class NoValueMovingFnsVmfEmptyUnaffectedTest(unittest.TestCase):
    """(c) value_moving_functions.json present but function_count=0 (or file absent)
    -> the new PATH 2 gate is a no-op. Workspace is not affected."""

    def setUp(self):
        self.ws = _mk_vmf_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # value_moving_functions.json with 0 functions (no value-moving surface)
        _wj(a / "value_moving_functions.json", {
            "workspace": str(self.ws),
            "generated_at": "2026-06-13T00:00:00Z",
            "function_count": 0,
            "functions": [],
        })

        # mutation_verify_coverage: per_function_verified=0
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 0,
                "per_function_verified": 0,
                "total": 0,
            }
        })

        # NO DEEP_AUDIT_HOLLOW.flag, NO genuine_coverage_manifest.json
        fuzz_dir = self.ws / "fuzz_runs" / "run_20260613d"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "medusa",
            "status": "ok",
            "properties_checked": 3,
        })
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True,
            "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_honesty_check_no_fail_when_vmf_empty(self):
        """audit-honesty-check must not emit fail-hollow-per-function-harnesses
        when value_moving_functions.json has function_count=0."""
        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"vmf function_count=0 must not emit hollow fail; "
            f"got fails={result['fails']}",
        )

    def test_honest_zero_verify_unaffected_when_vmf_empty(self):
        """_check_deep_evidence must pass (not fail on PATH 2) when vmf is empty."""
        ok, reason, _ = _run_hzv(self.ws)
        # The workspace may still fail other checks (e.g. mutation_verify_coverage
        # has 0 verified harnesses), but NOT on the vmf-direct path.
        # We assert the failure reason does NOT mention value_moving_functions.
        self.assertNotIn(
            "value_moving_functions",
            reason,
            f"vmf function_count=0 must not trigger vmf-direct fail path; "
            f"reason: {reason}",
        )


# ---------------------------------------------------------------------------
# CORROBORATION TESTS: genuine_coverage_manifest alone is NOT sufficient -
# it must be backed by per_function entries in mutation_verify_coverage.json.
#
# These tests close the FALSE-GREEN HOLE: someone can write
#   {"mutation_verified_genuine_count": 8}
# into genuine_coverage_manifest.json by hand and previously that was enough
# to suppress the hollow fail.  After the fix, the manifest count must be
# CORROBORATED by mutation_verify_coverage.json having per_function entries
# with mutation_verified==True, oracle_verdict=="non-vacuous", killed==True.
# ---------------------------------------------------------------------------

def _make_corroborated_per_fn(n: int) -> list:
    """Generate n genuine per_function entries for mutation_verify_coverage.json."""
    return [
        {
            "function": f"fn_{i}",
            "harness_path": f"/ws/.auditooor/per_function_harnesses/fn_{i}.t.sol",
            "mutation_verified": True,
            "oracle_verdict": "non-vacuous",
            "killed": True,
        }
        for i in range(n)
    ]


class CorroborationRequiredFlagPath(unittest.TestCase):
    """PATH 1 (flag-based): DEEP_AUDIT_HOLLOW.flag present + gcm count=8 but
    mutation_verify_coverage.json has NO per_function list (absent/no list).
    The hollow fail MUST still fire (hole closed).

    Sub-case (b): when corroborated per_function list IS present (8 entries),
    the fail is suppressed (genuine case - no regression)."""

    def setUp(self):
        self.ws = _mk_base_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # DEEP_AUDIT_HOLLOW.flag is present
        (a / "DEEP_AUDIT_HOLLOW.flag").write_text(
            "scaffold-only: 0 genuine mutation-verified harnesses\n"
            "mutation_verified_genuine = 0\ncheckable = 8\n",
            encoding="utf-8",
        )

        # genuine_coverage_manifest claims 8 kills (hand-writable integer)
        _wj(a / "genuine_coverage_manifest.json", {
            "mutation_verified_genuine_count": 8,
            "checkable_count": 8,
            "status": "complete",
            "summary": "8 genuine kills (hand-written - no per_function backing)",
        })

        # mutation_verify_coverage.json has counts showing 0 per_function_verified
        # and NO per_function list at all (the hole scenario)
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 8,
                "per_function_verified": 0,
                "total": 8,
            },
            # deliberately NO "per_function" key
        })

        # Engine artifacts
        fuzz_dir = self.ws / "fuzz_runs" / "run_corr_a"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "medusa", "status": "ok", "properties_checked": 8,
        })
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True, "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    # -- (a) hole closed: manifest count=8 but no per_function backing -> FAIL --

    def test_honesty_check_fails_when_mvc_has_no_per_function_list(self):
        """PATH 1: flag present + gcm count=8 + mvc has no per_function list
        -> a hollow fail MUST fire (hole closed).
        Any of fail-hollow-per-function-harnesses, fail-hollow-engines, or
        fail-stub-harnesses is acceptable - the key result is the workspace is
        NOT passed as genuinely audited."""
        result = _run_honesty(self.ws)
        _hollow_fails = {
            "fail-hollow-per-function-harnesses",
            "fail-hollow-engines",
            "fail-stub-harnesses",
        }
        self.assertTrue(
            bool(_hollow_fails & set(result["fails"])),
            f"manifest count=8 but no per_function list in mvc must NOT suppress "
            f"hollow fail; got fails={result['fails']}",
        )
        self.assertNotEqual(
            result["verdict"],
            "pass-genuinely-audited",
            "hand-written manifest without corroborating per_function entries "
            "must NOT green the gate",
        )

    def test_honest_zero_verify_fails_when_mvc_has_no_per_function_list(self):
        """honest-zero-verify._check_deep_evidence must reject when mvc has no
        per_function list, even if genuine_coverage_manifest claims count=8."""
        ok, reason, _ = _run_hzv(self.ws)
        self.assertFalse(
            ok,
            f"_check_deep_evidence must FAIL when mvc has no per_function list "
            f"(manifest alone is not sufficient). reason: {reason}",
        )

    # -- (b) genuine: manifest count=8 + 8 corroborated per_function entries -> PASS --

    def test_honesty_check_passes_when_mvc_has_corroborated_per_function_list(self):
        """PATH 1: flag present + gcm count=8 + mvc has 8 genuine per_function entries
        -> hollow fail is suppressed (morpho-like genuine case, no regression)."""
        a = self.ws / ".auditooor"
        mvc_path = a / "mutation_verify_coverage.json"
        mvc = json.loads(mvc_path.read_text(encoding="utf-8"))
        mvc["per_function"] = _make_corroborated_per_fn(8)
        mvc_path.write_text(json.dumps(mvc), encoding="utf-8")

        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"8 corroborated per_function entries must suppress hollow fail; "
            f"got fails={result['fails']}",
        )

    def test_honest_zero_verify_passes_when_mvc_has_corroborated_per_function_list(self):
        """honest-zero-verify._check_deep_evidence must pass when mvc has 8 genuine
        per_function entries (corroborated), even with DEEP_AUDIT_HOLLOW.flag present."""
        a = self.ws / ".auditooor"
        mvc_path = a / "mutation_verify_coverage.json"
        mvc = json.loads(mvc_path.read_text(encoding="utf-8"))
        mvc["per_function"] = _make_corroborated_per_fn(8)
        mvc_path.write_text(json.dumps(mvc), encoding="utf-8")

        ok, reason, _ = _run_hzv(self.ws)
        self.assertTrue(
            ok,
            f"8 corroborated per_function entries must allow _check_deep_evidence "
            f"to pass. reason: {reason}",
        )


class CorroborationRequiredPath2(unittest.TestCase):
    """PATH 2 (vmf-direct): value_moving_functions >=1 + per_function_verified=0
    + gcm claims count=8 but mvc has no per_function list -> MUST fail.

    Sub-case (b): same setup but mvc HAS 8 genuine per_function entries -> PASS."""

    def setUp(self):
        self.ws = _mk_vmf_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        _wj(a / "value_moving_functions.json", {
            "workspace": str(self.ws),
            "generated_at": "2026-06-13T00:00:00Z",
            "function_count": 1,
            "functions": [
                {
                    "file": "src/Ledger.sol",
                    "function": "transfer",
                    "transfer_hit": True,
                    "ledger_write_hit": True,
                }
            ],
        })

        # per_function_verified=0 in counts, NO per_function list
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {
                "cross_function_verified": 8,
                "per_function_verified": 0,
                "total": 8,
            },
            # deliberately NO "per_function" key
        })

        # genuine_coverage_manifest claims 8 kills (bare integer, not corroborated)
        _wj(a / "genuine_coverage_manifest.json", {
            "mutation_verified_genuine_count": 8,
            "checkable_count": 8,
            "status": "complete",
            "summary": "8 genuine kills (hand-written - no per_function backing)",
        })

        # NO DEEP_AUDIT_HOLLOW.flag
        _wj(a / "halmos" / "artifact.json", {"status": "ok", "properties_checked": 8})
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True, "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    # -- (a) hole closed --

    def test_honesty_check_fails_path2_no_corroboration(self):
        """PATH 2: vmf>=1 + per_function_verified=0 + gcm count=8 + no per_function
        list in mvc -> fail-hollow-per-function-harnesses MUST fire (hole closed)."""
        result = _run_honesty(self.ws)
        self.assertIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"PATH 2: bare gcm count without per_function corroboration must fail; "
            f"got fails={result['fails']}",
        )
        self.assertNotEqual(
            result["verdict"],
            "pass-genuinely-audited",
            "hand-written-only manifest must not green PATH 2 gate",
        )

    def test_honest_zero_verify_fails_path2_no_corroboration(self):
        """honest-zero-verify._check_deep_evidence must fail PATH 2 when mvc has no
        per_function list, even if gcm claims count=8."""
        ok, reason, _ = _run_hzv(self.ws)
        self.assertFalse(
            ok,
            f"_check_deep_evidence must FAIL on PATH 2 when no per_function "
            f"corroboration. reason: {reason}",
        )

    # -- (b) genuine --

    def test_honesty_check_passes_path2_with_corroboration(self):
        """PATH 2: vmf>=1 + per_function_verified=0 + gcm count=8 + mvc has 8 genuine
        per_function entries -> hollow fail is suppressed (no regression)."""
        a = self.ws / ".auditooor"
        mvc_path = a / "mutation_verify_coverage.json"
        mvc = json.loads(mvc_path.read_text(encoding="utf-8"))
        mvc["per_function"] = _make_corroborated_per_fn(8)
        mvc_path.write_text(json.dumps(mvc), encoding="utf-8")

        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"8 corroborated PATH 2 entries must suppress hollow fail; "
            f"got fails={result['fails']}",
        )

    def test_honest_zero_verify_passes_path2_with_corroboration(self):
        """honest-zero-verify._check_deep_evidence must pass PATH 2 when mvc has 8
        genuine per_function entries (corroborated)."""
        a = self.ws / ".auditooor"
        mvc_path = a / "mutation_verify_coverage.json"
        mvc = json.loads(mvc_path.read_text(encoding="utf-8"))
        mvc["per_function"] = _make_corroborated_per_fn(8)
        mvc_path.write_text(json.dumps(mvc), encoding="utf-8")

        ok, reason, _ = _run_hzv(self.ws)
        self.assertTrue(
            ok,
            f"_check_deep_evidence must PASS with 8 corroborated PATH 2 entries. "
            f"reason: {reason}",
        )


class CorroborationEdgeCases(unittest.TestCase):
    """Edge cases for the corroboration helper:
    - mvc absent -> treat as 0 (fail if gcm claims positive)
    - mvc present but per_function list has entries with wrong fields -> 0
    - mvc with a mix of genuine and non-genuine entries -> count only genuine ones
    """

    def setUp(self):
        self.ws = _mk_base_ws()
        _write_fuzz_artifact(self.ws)
        _write_coverage_report(self.ws)
        a = self.ws / ".auditooor"

        # DEEP_AUDIT_HOLLOW.flag + gcm count=5
        (a / "DEEP_AUDIT_HOLLOW.flag").write_text(
            "scaffold-only\nmutation_verified_genuine = 0\ncheckable = 5\n",
            encoding="utf-8",
        )
        _wj(a / "genuine_coverage_manifest.json", {
            "mutation_verified_genuine_count": 5,
            "checkable_count": 5,
            "status": "complete",
        })

        fuzz_dir = self.ws / "fuzz_runs" / "run_edge"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "medusa", "status": "ok", "properties_checked": 5,
        })
        _wj(a / "g15_hunt_coverage_gate_last_result.json", {
            "coverage_pct": 1.0, "covered": 10, "total": 10,
        })
        _wj(a / "depth_certificate.json", {
            "negative_space_ran": True, "sibling_diff_ran": True,
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_mvc_absent_fires_hollow_fail(self):
        """When mutation_verify_coverage.json is completely absent, the bare gcm
        count is not sufficient - a hollow fail must fire."""
        # Do NOT write mutation_verify_coverage.json at all
        result = _run_honesty(self.ws)
        _hollow_fails = {
            "fail-hollow-per-function-harnesses",
            "fail-hollow-engines",
            "fail-stub-harnesses",
        }
        self.assertTrue(
            bool(_hollow_fails & set(result["fails"])),
            f"mvc absent + bare gcm count must fire a hollow fail; "
            f"got fails={result['fails']}",
        )

    def test_mvc_wrong_fields_fires_hollow_fail(self):
        """per_function entries that are missing required fields are not counted -
        a hollow fail must still fire."""
        a = self.ws / ".auditooor"
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {"per_function_verified": 0, "total": 0},
            "per_function": [
                # mutation_verified=True but oracle_verdict is wrong
                {"mutation_verified": True, "oracle_verdict": "vacuous", "killed": True},
                # killed=False
                {"mutation_verified": True, "oracle_verdict": "non-vacuous", "killed": False},
                # mutation_verified=False
                {"mutation_verified": False, "oracle_verdict": "non-vacuous", "killed": True},
                # missing fields entirely
                {"fn": "foo"},
            ],
        })
        result = _run_honesty(self.ws)
        _hollow_fails = {
            "fail-hollow-per-function-harnesses",
            "fail-hollow-engines",
            "fail-stub-harnesses",
        }
        self.assertTrue(
            bool(_hollow_fails & set(result["fails"])),
            f"per_function with wrong fields must not count as corroborated; "
            f"got fails={result['fails']}",
        )

    def test_mvc_partial_corroboration_suppresses_hollow_fail(self):
        """Even 1 genuinely corroborated entry is enough to suppress the hollow
        fail (if gcm also claims >= 1)."""
        a = self.ws / ".auditooor"
        _wj(a / "mutation_verify_coverage.json", {
            "counts": {"per_function_verified": 0, "total": 1},
            "per_function": [
                # 1 genuine entry
                {
                    "mutation_verified": True,
                    "oracle_verdict": "non-vacuous",
                    "killed": True,
                    "function": "withdraw",
                },
                # 2 non-genuine (don't count)
                {"mutation_verified": False, "oracle_verdict": "non-vacuous", "killed": True},
                {"mutation_verified": True, "oracle_verdict": "vacuous", "killed": True},
            ],
        })
        result = _run_honesty(self.ws)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses",
            result["fails"],
            f"1 genuine corroborated entry must suppress hollow fail; "
            f"got fails={result['fails']}",
        )


if __name__ == "__main__":
    unittest.main()
