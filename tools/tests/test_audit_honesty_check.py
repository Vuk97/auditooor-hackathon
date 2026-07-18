#!/usr/bin/env python3
# r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
"""Tests for four bug-fixes in tools/audit-honesty-check.py.

FIX 1 - Go stale-manifest false-green
  audit_deep_all_manifest.json (language-agnostic orchestrator handoff, no engine field)
  should NOT certify a Go workspace as genuinely executed when there are zero real Go runs.
  Before fix: the `any(s in ("ok","pass","complete") for s in statuses.values())` disjunct
  would pick up the "ok" from audit_deep_all_manifest.json profiles and set real_execution=True.
  After fix: only go_engine_runs (engine-filtered) and _nonevm_engine_genuinely_executed drive
  real_execution, so a workspace with only a stale all-manifest returns real_execution=False.

FIX 2 - Dead code _norm_unit_key removed
  _norm_unit_key had zero call sites and a no-op body (s.strip() only). Deleted.
  The real normalization lives in _unit_match_keys; we guard its contract.

FIX 3 - Stale harness_path silently skipped
  When a per_function manifest.json lists harness_path entries that do not exist on disk,
  they were silently skipped, leaving stub=0 and preventing fail-stub-harnesses from firing.
  After fix each broken path increments stub.

FIX 4 - Missing coverage gate false-green
  When .auditooor/g15_hunt_coverage_gate_last_result.json is absent AND engines genuinely
  ran, the old code would return verdict="pass-genuinely-audited" with no coverage evidence.
  After fix: _true_coverage returns gate_file_missing=True and check() fires
  fail-no-coverage-gate, blocking pass-genuinely-audited.
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
_TOOL = _REPO / "tools" / "audit-honesty-check.py"


def _run(ws: Path) -> dict:
    """Run audit-honesty-check.py --json against ws and return parsed result."""
    cp = subprocess.run(
        [sys.executable, str(_TOOL), "--workspace", str(ws), "--json"],
        capture_output=True,
        text=True,
    )
    if not cp.stdout.strip():
        raise AssertionError(
            f"no JSON on stdout (rc={cp.returncode}); stderr=\n{cp.stderr[:500]}"
        )
    return json.loads(cp.stdout)


def _wj(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def _mk_ws(lang: str = "go") -> Path:
    """Create a minimal temporary workspace with a single source file."""
    ws = Path(tempfile.mkdtemp(prefix="ahc_test_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(parents=True, exist_ok=True)
    if lang == "go":
        (ws / "go.mod").write_text("module example.com/test\ngo 1.21\n", encoding="utf-8")
        (ws / "src" / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    elif lang == "solidity":
        (ws / "src" / "X.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract X { function f() external {} }\n",
            encoding="utf-8",
        )
    return ws


# ---------------------------------------------------------------------------
# FIX 1: Go arm - stale audit_deep_all_manifest.json must not credit real_execution
# ---------------------------------------------------------------------------

class Fix1GoStaleManifestTest(unittest.TestCase):
    """audit_deep_all_manifest.json with ok profiles must NOT drive real_execution=True
    for a Go workspace with zero actual Go engine runs."""

    def setUp(self):
        self.ws = _mk_ws(lang="go")
        # Write ONLY audit_deep_all_manifest.json (the language-agnostic orchestrator
        # handoff packet). It has profiles with status=success, but NO engine field.
        # This is the exact stale-manifest scenario the fix addresses.
        _wj(
            self.ws / ".audit_logs" / "audit_deep_all_manifest.json",
            {"profiles": [{"status": "success", "exit_code": 0}]},
        )
        # Confirm: no fuzz_runs/ directory, no go-engine manifest.

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_go_stale_manifest_does_not_credit_real_execution(self):
        """After fix: real_execution must be False; before fix it was True."""
        result = _run(self.ws)
        eng = result["engines"]
        self.assertFalse(
            eng["real_execution"],
            f"stale audit_deep_all_manifest.json MUST NOT credit real_execution=True "
            f"for a Go workspace with zero Go engine runs. got: {eng}",
        )
        # The workspace should report fail-hollow-engines (or contain it in fails).
        self.assertIn("fail-hollow-engines", result["fails"],
                      f"expected fail-hollow-engines in fails, got: {result['fails']}")
        self.assertNotEqual(
            result["verdict"], "pass-genuinely-audited",
            "A Go workspace with only a stale all-manifest must not pass as genuinely audited",
        )

    def test_go_real_engine_run_still_credits_real_execution(self):
        """Control: a Go workspace with a genuine go-dynamic engine run IS credited."""
        fuzz_dir = self.ws / "fuzz_runs" / "run_20260610_120000"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "go-dynamic",
            "status": "pass",
            "tests_passed": 5,
        })
        result = _run(self.ws)
        eng = result["engines"]
        self.assertTrue(
            eng["real_execution"],
            f"a genuine go-dynamic run MUST credit real_execution=True, got: {eng}",
        )


# ---------------------------------------------------------------------------
# FIX 2: _norm_unit_key deleted; _unit_match_keys contract guarded
# ---------------------------------------------------------------------------

class Fix2NormUnitKeyDeletedTest(unittest.TestCase):
    """_norm_unit_key is deleted (dead code). _unit_match_keys still works correctly."""

    def setUp(self):
        # Load the module in-process to test internal functions.
        # Register in sys.modules before exec_module to satisfy Python 3.14
        # dataclass module-dict resolution.
        mod_name = "_ahc_fix2_test_mod"
        if mod_name not in sys.modules:
            spec = importlib.util.spec_from_file_location(mod_name, _TOOL)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
        self.mod = sys.modules[mod_name]

    def test_norm_unit_key_does_not_exist(self):
        """_norm_unit_key was dead code and has been removed."""
        self.assertFalse(
            hasattr(self.mod, "_norm_unit_key"),
            "_norm_unit_key must be deleted (it was dead code with zero call sites)",
        )

    def test_unit_match_keys_full_and_basename(self):
        """_unit_match_keys produces both full-path and basename forms."""
        keys = self.mod._unit_match_keys("A/src/x.sol", "fn")
        self.assertIn("A/src/x.sol::fn", keys,
                      "_unit_match_keys must include the full relpath form")
        self.assertIn("x.sol::fn", keys,
                      "_unit_match_keys must include the basename form")

    def test_unit_match_keys_empty_inputs(self):
        """Empty file or function returns empty set."""
        self.assertEqual(self.mod._unit_match_keys("", "fn"), set())
        self.assertEqual(self.mod._unit_match_keys("x.sol", ""), set())
        self.assertEqual(self.mod._unit_match_keys("", ""), set())

    def test_deep_covered_credits_function_coverage_real_attack(self):
        """_load_deep_covered_unit_keys credits a unit classified real-attack in
        function_coverage_completeness.json even when coverage_report.json's swept
        heatmap omits it (near-intents 2026-06-26: 29 hunted units under-credited)."""
        ws = Path(tempfile.mkdtemp(prefix="ahc_fcc_"))
        (ws / ".auditooor").mkdir(parents=True)
        _wj(ws / ".auditooor" / "coverage_report.json", {"covered_units": []})
        _wj(ws / ".auditooor" / "function_coverage_completeness.json", {
            "functions": [
                {"file": "src/x/lib.rs", "name": "get_token_id", "classification": "real-attack"},
                {"file": "src/x/lib.rs", "name": "untouched_fn", "classification": "untouched"},
            ]})
        keys = self.mod._load_deep_covered_unit_keys(ws)
        self.assertIn("src/x/lib.rs::get_token_id", keys)
        self.assertNotIn("src/x/lib.rs::untouched_fn", keys,
                         "untouched fns must NOT be credited as covered")

    def test_deep_covered_credits_hunt_sidecar_terminal_verdict(self):
        """A per-fn hunt sidecar with a terminal verdict + real anchor credits its
        unit even when function-coverage's enumeration omits it (Solana entrypoints /
        view getters)."""
        ws = Path(tempfile.mkdtemp(prefix="ahc_sc_"))
        scd = ws / ".auditooor" / "hunt_findings_sidecars"
        scd.mkdir(parents=True)
        _wj(scd / "sc1.json", {
            "function_anchor": {"file": "src/sol/lib.rs", "fn": "set_derived_near_bridge_address"},
            "result": {"verdict": "KILL", "applies_to_target": "no", "file_line": "src/sol/lib.rs:5"}})
        keys = self.mod._load_deep_covered_unit_keys(ws)
        self.assertIn("src/sol/lib.rs::set_derived_near_bridge_address", keys)


# ---------------------------------------------------------------------------
# FIX 3: Broken harness_path increments stub count
# ---------------------------------------------------------------------------

class Fix3BrokenHarnessPathCountsAsStubTest(unittest.TestCase):
    """A per_function manifest.json whose harness_path entries point to non-existent
    files must increment stub, not silently disappear."""

    def setUp(self):
        self.ws = _mk_ws(lang="solidity")
        # Write a per_function_invariants manifest claiming 2 harnesses at
        # non-existent paths. No actual .t.sol files anywhere on disk.
        pfi_dir = self.ws / ".auditooor" / "per_function_invariants"
        pfi_dir.mkdir(parents=True, exist_ok=True)
        _wj(pfi_dir / "manifest.json", {
            "functions": [
                {
                    "name": "fn1",
                    "harness_path": str(self.ws / "nonexistent" / "fn1.t.sol"),
                },
                {
                    "name": "fn2",
                    "harness_path": str(self.ws / "nonexistent" / "fn2.t.sol"),
                },
            ]
        })

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_broken_harness_paths_counted_as_stubs(self):
        """After fix: stub_harnesses >= 2 for two broken harness_path entries."""
        result = _run(self.ws)
        pf = result["engines"]["per_function"]
        self.assertGreaterEqual(
            pf.get("stub_harnesses", 0), 2,
            f"two broken harness_path entries must produce stub_harnesses >= 2, "
            f"got per_function={pf}",
        )

    def test_broken_harness_paths_trigger_fail_stub_or_hollow(self):
        """After fix: a workspace with only broken harness_path stubs must not
        pass as genuinely audited."""
        result = _run(self.ws)
        # Either fail-stub-harnesses or fail-hollow-engines is acceptable
        # (both indicate the workspace is not genuinely audited).
        hollow_or_stub = (
            "fail-stub-harnesses" in result["fails"]
            or "fail-hollow-engines" in result["fails"]
        )
        self.assertTrue(
            hollow_or_stub,
            f"broken harness_path stubs must produce a hollow/stub fail, "
            f"got fails={result['fails']}, verdict={result['verdict']}",
        )
        self.assertNotEqual(
            result["verdict"], "pass-genuinely-audited",
            "a workspace with only broken harness_path stubs must not pass",
        )


# ---------------------------------------------------------------------------
# FIX 5: Authored engine execution suppresses duplicate stub-only failure
# ---------------------------------------------------------------------------

class Fix5AuthoredEngineServingJoinTest(unittest.TestCase):
    """A real authored engine run must not be mislabeled stub-only because
    generated per-function scaffolds are also present."""

    def setUp(self):
        self.ws = _mk_ws(lang="solidity")
        root = self.ws / "poc-tests" / "real-engine-harness"
        (root / "test").mkdir(parents=True, exist_ok=True)
        (root / "test" / "Real.t.sol").write_text(
            "pragma solidity ^0.8.0; contract Real { function testFuzz_real(uint256 x) public { assertEq(x, x); } }\n",
            encoding="utf-8",
        )
        _wj(self.ws / ".auditooor" / "solidity-deep-audit" / "engine-harness-execution.json", {
            "schema": "auditooor.engine_harness_execution.v1",
            "executed_engine_harness_count": 1,
            "harnesses": [{"root": str(root), "status": "pass", "tests_passed": 1}],
        })
        pfi = self.ws / ".auditooor" / "per_function_invariants"
        pfi.mkdir(parents=True, exist_ok=True)
        (pfi / "Generated.t.sol").write_text(
            "// Auto-generated by tools/per-function-invariant-gen.py\nassert(true);\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_authored_run_serves_real_execution_join(self):
        result = _run(self.ws)
        self.assertTrue(result["engines"].get("authored_engine_harnesses_credited"))
        self.assertNotIn("fail-stub-harnesses", result["fails"])

    def test_workspace_relative_root_serves_real_execution_join(self):
        execution = self.ws / ".auditooor" / "solidity-deep-audit" / "engine-harness-execution.json"
        data = json.loads(execution.read_text(encoding="utf-8"))
        data["harnesses"][0]["root"] = "poc-tests/real-engine-harness"
        execution.write_text(json.dumps(data), encoding="utf-8")

        result = _run(self.ws)
        self.assertTrue(result["engines"].get("authored_engine_harnesses_credited"))
        self.assertNotIn("fail-stub-harnesses", result["fails"])


# ---------------------------------------------------------------------------
# FIX 4: Missing coverage gate fires fail-no-coverage-gate
# ---------------------------------------------------------------------------

class Fix4MissingCoverageGateTest(unittest.TestCase):
    """When g15 gate file is absent but engines genuinely ran, check() must fire
    fail-no-coverage-gate and must NOT return pass-genuinely-audited."""

    def _make_ws_with_real_engine(self) -> Path:
        """Go workspace with a genuine go-dynamic engine run but no g15 gate file."""
        ws = _mk_ws(lang="go")
        fuzz_dir = ws / "fuzz_runs" / "run_20260610_130000"
        fuzz_dir.mkdir(parents=True, exist_ok=True)
        _wj(fuzz_dir / "manifest.json", {
            "engine": "go-dynamic",
            "status": "pass",
            "tests_passed": 3,
        })
        # Explicitly confirm the gate file does NOT exist.
        gate = ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
        assert not gate.exists(), "gate file must be absent for this test"
        return ws

    def test_missing_gate_fires_fail_no_coverage_gate(self):
        """Engines ran but g15 gate absent -> fail-no-coverage-gate in fails."""
        ws = self._make_ws_with_real_engine()
        try:
            result = _run(ws)
            self.assertIn(
                "fail-no-coverage-gate", result["fails"],
                f"expected fail-no-coverage-gate in fails, got: {result['fails']}",
            )
            self.assertNotEqual(
                result["verdict"], "pass-genuinely-audited",
                "must not pass as genuinely audited when coverage gate is missing",
            )
            self.assertTrue(
                result["coverage"].get("gate_file_missing"),
                "coverage.gate_file_missing must be True when the gate file is absent",
            )
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_present_gate_does_not_fire_fail_no_coverage_gate(self):
        """Control: gate file present -> fail-no-coverage-gate NOT in fails."""
        ws = self._make_ws_with_real_engine()
        try:
            # Write a minimal g15 gate file with full coverage.
            _wj(
                ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json",
                {
                    "coverage_pct": 1.0,
                    "total_units": 1,
                    "covered": 1,
                    "budget_skipped_units": [],
                },
            )
            result = _run(ws)
            self.assertNotIn(
                "fail-no-coverage-gate", result["fails"],
                f"fail-no-coverage-gate must NOT fire when gate file exists, "
                f"got fails={result['fails']}",
            )
            self.assertFalse(
                result["coverage"].get("gate_file_missing"),
                "coverage.gate_file_missing must be False when the gate file exists",
            )
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_missing_gate_no_engines_no_false_penalty(self):
        """Control: gate absent but engines also absent -> fail-hollow-engines fires
        (the existing gate) but fail-no-coverage-gate must NOT (real_execution=False,
        the gating condition is not met - no double-penalty)."""
        ws = _mk_ws(lang="go")
        # No engine run, no gate file.
        try:
            result = _run(ws)
            self.assertNotIn(
                "fail-no-coverage-gate", result["fails"],
                f"fail-no-coverage-gate must not fire when engines also did not run, "
                f"got fails={result['fails']}",
            )
            self.assertIn(
                "fail-hollow-engines", result["fails"],
                "fail-hollow-engines must fire when engines did not run",
            )
        finally:
            shutil.rmtree(ws, ignore_errors=True)


class MutationVerifyCutCreditTest(unittest.TestCase):
    """A standalone mutation-verify-coverage.v1 CUT harness (e.g. a Foundry core
    invariant test like ProtocolFee_CoreInvariant, proven non-vacuous: baseline
    pass + killed mutant) is the un-fakeable ground truth. audit-honesty-check must
    credit it as a real in-scope harness + a corroborated genuine count, so the
    coverage-theater gates (fail-stub-harnesses / fail-hollow-per-function) do not
    fire on a workspace whose genuine harness is a Foundry invariant test."""

    def _load_mod(self):
        spec = importlib.util.spec_from_file_location("_ahc_mvc", _TOOL)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def _mk(self, killed=True):
        ws = Path(tempfile.mkdtemp(prefix="ahc_mvc_"))
        cut = ws / "src" / "Fee.sol"
        cut.parent.mkdir(parents=True)
        cut.write_text("contract Fee {}\n")
        rec = {
            "schema": "auditooor.mutation_verify_coverage.v1",
            "verdict": "non-vacuous",
            "source_file": str(cut),
            "function": "_setFee",
            "baseline": {"status": "pass"},
            "mutant_results": [{"mutant_id": "m0", "killed": killed}],
        }
        d = ws / ".auditooor" / "cross-function-coverage"
        d.mkdir(parents=True)
        (d / "fee.json").write_text(json.dumps(rec))
        return ws

    def test_credits_real_inscope_and_corroborated(self):
        import importlib.util  # noqa: F401 (ensure available)
        m = self._load_mod()
        ws = self._mk(killed=True)
        self.assertEqual(len(m._mutation_verified_cut_harnesses(ws)), 1)
        self.assertGreaterEqual(m._corroborated_genuine_count(ws), 1)

    def test_unkilled_mutant_not_credited(self):
        m = self._load_mod()
        ws = self._mk(killed=False)
        self.assertEqual(m._mutation_verified_cut_harnesses(ws), [])


if __name__ == "__main__":
    import importlib.util  # noqa: F401
    unittest.main()


class TestFccEnumerationDenominatorFilter(unittest.TestCase):
    """NUVA 2026-06-30: audit-honesty's coverage denominator must DEFER to function-
    coverage's authoritative attack-surface enumeration. inscope_units.jsonl enumerates
    ALL functions (incl. internal `_`-helpers, constructors, pure libraries, interface
    decls, view getters) which fcc deliberately drops as non-attack-surface; counting
    them read coverage-below-100 even when fcc is pass-fully-covered (171/171)."""

    def _load_mod(self):
        spec = importlib.util.spec_from_file_location("ah_filter", _TOOL)
        m = importlib.util.module_from_spec(spec)
        sys.modules["ah_filter"] = m
        spec.loader.exec_module(m)
        return m

    def test_fcc_keys_exclude_internal_and_credit_attack_surface(self):
        m = self._load_mod()
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            au = ws / ".auditooor"
            au.mkdir(parents=True)
            # fcc enumerates ONLY the external attack surface (deposit/withdraw)
            _wj(au / "function_coverage_completeness.json", {
                "verdict": "pass-fully-covered",
                "functions": [
                    {"file": "src/V.sol", "name": "deposit", "classification": "real-attack"},
                    {"file": "src/V.sol", "name": "withdraw", "classification": "real-attack"},
                ] + [{"file": "src/V.sol", "name": f"f{i}", "classification": "real-attack"} for i in range(8)],
            })
            keys = m._fcc_enumerated_keys(ws)
            self.assertIn("src/V.sol::deposit", keys)
            self.assertIn("V.sol::withdraw", keys)
            # an internal helper fcc did NOT enumerate is absent -> would be filtered out
            self.assertNotIn("src/V.sol::_verifyAML", keys)

    def test_missing_fcc_artifact_yields_empty_keys_no_filter(self):
        m = self._load_mod()
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(m._fcc_enumerated_keys(Path(t)), set())
