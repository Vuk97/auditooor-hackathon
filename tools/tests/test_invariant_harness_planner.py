#!/usr/bin/env python3
"""
test_invariant_harness_planner.py — PR #526 gap 3 tests.

Covers:
  * synthetic 5-row ledger -> 5 plans, all required fields present
  * FN7-shape (BASE-DLT-WITHDRAWALS-ROOT) -> engine_api_in_process
  * BASE-SC-PROOF-DOMAIN -> forge_invariant
  * POLY-LIVE-ROLE-CONFIG -> live_check
  * idempotence: re-run on unchanged ledger -> byte-identical manifest
  * speed-up demo: real base-azul ledger plan for BASE-DLT-I01 surfaces
    engine_api_in_process directly (saves the broader-RPC cycles)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "invariant-harness-planner.py"

REQUIRED_PLAN_FIELDS = (
    "row_id",
    "harness_family",
    "reason",
    "required_fixtures",
    "target_entrypoint",
    "minimal_proof_surface",
    "compile_command",
    "first_negative_control",
    "expected_log_string",
    "stop_condition",
    "source_row_status",
    "source_invariant_family",
    "foundry_profile_hints",
)


def _row(rid: str, family: str, statement: str, *,
         status: str = "missing_harness",
         production_path: str = "",
         harness_target: str = "",
         negative_test: str = "",
         required_engine: str = "manual",
         severity: str = "Medium") -> dict:
    """Build a synthetic ledger row that satisfies the v1 schema's
    required-field set (the planner doesn't validate; we still construct
    a realistic row so the heuristic has something to chew on)."""
    return {
        "id": rid,
        "scope_asset": "synthetic",
        "invariant_family": family,
        "statement": statement,
        "source_citations": ["docs/test.md"],
        "attacker_capability": "user input",
        "trusted_boundary": "none",
        "oos_boundary": "in scope",
        "production_path": production_path or f"src/{rid.lower()}.rs",
        "harness_target": harness_target,
        "required_engine": required_engine,
        "negative_test": negative_test,
        "status": status,
        "artifacts": [],
        "owner": "Claude",
        "severity": severity,
    }


def _write_ledger(ws: Path, rows: list) -> Path:
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    p = auditooor_dir / "invariant_ledger.json"
    p.write_text(json.dumps({
        "schema_version": "auditooor.invariant_ledger.v1",
        "schema_source": "test",
        "workspace": str(ws),
        "generated_by": "test_invariant_harness_planner",
        "generated_at": "2026-04-29T00:00:00Z",
        "rows": rows,
    }, indent=2, sort_keys=True) + "\n")
    return p


def _run_planner(ws: Path, *extra) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(TOOL), "--workspace", str(ws)] + list(extra)
    return subprocess.run(cmd, capture_output=True, text=True, check=True)


def _read_manifest(ws: Path) -> dict:
    return json.loads((ws / ".auditooor" / "harness_plans.json").read_text())


# ---------------------------------------------------------------------------

class TestPlannerSynthetic(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        # Five rows of varying families. Each one drives a different
        # heuristic branch.
        self.rows = [
            # 1. FN7-shape: DLT + engine-api / withdrawals-root
            _row("BASE-DLT-I01", "BASE-DLT-WITHDRAWALS-ROOT",
                 "Engine API newPayloadV4 with mismatched withdrawals-root "
                 "must be rejected before promotion via FCU.",
                 production_path="engine_newPayloadV4 -> reth on_new_payload "
                                 "-> validator.validate_payload",
                 harness_target="EXPECTED: poc-tests/fn7_engine_tree_e2e.rs"),
            # 2. SC + proof_domain
            _row("BASE-SC-I01", "BASE-SC-PROOF-DOMAIN",
                 "AggregateVerifier.verify must dispatch to the correct "
                 "verifier for the proof_domain claimed by the proposer.",
                 production_path="external/contracts/src/AggregateVerifier.sol",
                 harness_target="EXPECTED: external/contracts/test/"
                                "invariants/Invariant_AggregateVerifier_"
                                "ProofDomain.t.sol"),
            # 3. LIVE row
            _row("POLY-LIVE-ROLE-CONFIG", "live_role_config_truth",
                 "Pause role on CTF must be the multisig deployment value, "
                 "not a stale single-signer EOA.",
                 production_path="external/exchange/src/Auth.sol",
                 harness_target="EXPECTED: live-check at "
                                ".auditooor/live_topology_checks.json"),
            # 4. parity / differential
            _row("BASE-DLT-I02", "BASE-DLT-STATE-ROOT-PARITY",
                 "State-root computed by reth must match revm-oracle for "
                 "every block in the corpus (no divergence).",
                 production_path="state_root parity vs revm-oracle",
                 harness_target="EXPECTED: differential_fuzz/"
                                "state_root_parity/Cargo.toml"),
            # 5. forge invariant family (CTF)
            _row("POLY-CTF-CONSERVATION", "ctf_collateral_conservation",
                 "CTF collateral conservation: sum(positions) == "
                 "totalCollateral after every action.",
                 production_path="external/conditional-tokens/src/"
                                 "ConditionalTokens.sol",
                 harness_target="EXPECTED: external/conditional-tokens/"
                                "test/invariants/Invariant_CTF_"
                                "Conservation.t.sol"),
        ]
        _write_ledger(self.ws, self.rows)

    def tearDown(self):
        self.tmp.cleanup()

    def test_planner_emits_five_plans(self):
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        self.assertEqual(manifest["plan_count"], 5)
        self.assertEqual(len(manifest["plans"]), 5)

    def test_each_plan_has_required_fields(self):
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        for plan in manifest["plans"]:
            for field in REQUIRED_PLAN_FIELDS:
                self.assertIn(field, plan,
                              f"plan for {plan.get('row_id')} missing "
                              f"field {field}")
            # required_fixtures must be a list (possibly empty)
            self.assertIsInstance(plan["required_fixtures"], list)
            # compile_command must be a non-empty string
            self.assertIsInstance(plan["compile_command"], str)
            self.assertTrue(plan["compile_command"].strip())

    def test_fn7_shape_maps_to_engine_api_in_process(self):
        """KEY assertion: a BASE-DLT-WITHDRAWALS-ROOT row gets
        engine_api_in_process, NOT forge_invariant. This is the core
        insight that would have saved FN7's broader-RPC cycles."""
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        plans = {p["row_id"]: p for p in manifest["plans"]}
        self.assertIn("BASE-DLT-I01", plans)
        self.assertEqual(plans["BASE-DLT-I01"]["harness_family"],
                         "engine_api_in_process",
                         "FN7-shape row must map to engine_api_in_process, "
                         "not forge_invariant or generic cargo_unit_test")
        # And NOT forge_invariant
        self.assertNotEqual(plans["BASE-DLT-I01"]["harness_family"],
                            "forge_invariant")

    def test_proof_domain_maps_to_forge_invariant(self):
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        plans = {p["row_id"]: p for p in manifest["plans"]}
        self.assertEqual(plans["BASE-SC-I01"]["harness_family"],
                         "forge_invariant")

    def test_live_role_maps_to_live_check(self):
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        plans = {p["row_id"]: p for p in manifest["plans"]}
        self.assertEqual(plans["POLY-LIVE-ROLE-CONFIG"]["harness_family"],
                         "live_check")

    def test_parity_row_maps_to_differential_fuzz(self):
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        plans = {p["row_id"]: p for p in manifest["plans"]}
        self.assertEqual(plans["BASE-DLT-I02"]["harness_family"],
                         "differential_fuzz")

    def test_ctf_row_maps_to_forge_invariant(self):
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        plans = {p["row_id"]: p for p in manifest["plans"]}
        self.assertEqual(plans["POLY-CTF-CONSERVATION"]["harness_family"],
                         "forge_invariant")

    def test_forge_plan_has_v17_profile_hints(self):
        _run_planner(self.ws)
        manifest = _read_manifest(self.ws)
        plans = {p["row_id"]: p for p in manifest["plans"]}
        hints = plans["POLY-CTF-CONSERVATION"]["foundry_profile_hints"]
        self.assertEqual(hints["planned_foundry_target"], "v1.7.1")
        self.assertEqual(hints["proof_profile"], "profile.invariants")
        self.assertIn("fuzz_seed", hints["required_metadata"])
        self.assertIn("--fuzz-seed <explicit-seed>", plans["POLY-CTF-CONSERVATION"]["compile_command"])

    def test_idempotent_rerun_is_byte_identical(self):
        _run_planner(self.ws)
        first = (self.ws / ".auditooor" / "harness_plans.json").read_bytes()
        _run_planner(self.ws)
        second = (self.ws / ".auditooor" / "harness_plans.json").read_bytes()
        self.assertEqual(first, second,
                         "re-running planner on unchanged ledger must "
                         "produce a byte-identical manifest")

    def test_typed_bridge_context_refines_proof_plan(self):
        row = _row(
            "BASE-DLT-LIFECYCLE", "async_lifecycle", "generic fallback",
            required_engine="cargo",
        )
        row["bridge_meta"] = {"obligation_context": {
            "expected_invariant": "both coupled writes commit or neither does",
            "kill_condition": "complete the pair without cancellation",
            "terminal_condition": "record a replayed schedule or a source-cited refutation",
        }}
        _write_ledger(self.ws, [row])
        _run_planner(self.ws)
        plan = _read_manifest(self.ws)["plans"][0]
        self.assertIn("both coupled writes commit", plan["minimal_proof_surface"])
        self.assertEqual(plan["first_negative_control"], "complete the pair without cancellation")
        self.assertEqual(plan["stop_condition"], "record a replayed schedule or a source-cited refutation")


class TestPlannerNeedsHumanFallback(unittest.TestCase):
    """A row whose family / id / statement matches no rule must emit
    `needs_human` with a reason — the planner is heuristic, not magic."""

    def test_unknown_family_yields_needs_human(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rows = [{
                "id": "MYSTERY-X-001",
                "scope_asset": "unknown",
                "invariant_family": "no_match_anywhere",
                "statement": "something must hold",
                "source_citations": ["docs/test.md"],
                "attacker_capability": "user",
                "trusted_boundary": "none",
                "oos_boundary": "in scope",
                "production_path": "src/mystery.py",
                "harness_target": "",
                "required_engine": "manual",
                "negative_test": "",
                "status": "missing_harness",
                "artifacts": [],
                "owner": "Claude",
            }]
            _write_ledger(ws, rows)
            _run_planner(ws)
            manifest = _read_manifest(ws)
            self.assertEqual(manifest["plan_count"], 1)
            plan = manifest["plans"][0]
            self.assertEqual(plan["harness_family"], "needs_human")
            self.assertTrue(plan["reason"])


class TestPlannerRequiredEngineFallback(unittest.TestCase):
    """Required-engine fallback (Lane-5 / Lane-10 capability gap fix).

    Bridge-promoted exploit-queue rows carry a ``required_engine`` field set
    by ``exploit-queue-to-invariant-ledger.py``.  When the keyword heuristic
    returns no match (attack_class is outside the id-segment and keyword
    tables), the planner must fall back to the ledger row's ``required_engine``
    value rather than emitting ``needs_human``.

    Cases:
      1. unknown attack_class + required_engine=forge  -> forge_invariant
      2. unknown attack_class + required_engine=go     -> cargo_unit_test
      3. unknown attack_class + required_engine=cargo  -> cargo_unit_test
      4. unknown attack_class + required_engine=manual -> needs_human (no fallback)
      5. keyword heuristic wins OVER required_engine (no regression):
         - SC in id segment + required_engine=forge -> forge_invariant (via SC branch)
         - DLT in id segment + no engine-api + required_engine=go -> cargo_unit_test
         - parity in statement + required_engine=forge -> differential_fuzz (keyword wins)
    """

    def _make_unknown_row(self, row_id: str, required_engine: str) -> dict:
        """Row with no id-segment family token and no keyword-matching statement."""
        return {
            "id": row_id,
            "scope_asset": "unknown_protocol",
            "invariant_family": "some_exotic_attack_class_not_in_any_table",
            "statement": "an exotic invariant property that matches no keyword",
            "source_citations": ["contracts/Exotic.sol"],
            "attacker_capability": "external user",
            "trusted_boundary": "none",
            "oos_boundary": "in scope",
            "production_path": "contracts/Exotic.sol:42",
            "harness_target": "",
            "required_engine": required_engine,
            "negative_test": "",
            "status": "missing_harness",
            "artifacts": [],
            "owner": "exploit-queue-bridge",
            "severity": "High",
        }

    def _plan_single_row(self, row: dict) -> dict:
        """Write a single-row ledger, run planner, return the plan dict."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_ledger(ws, [row])
            _run_planner(ws)
            manifest = _read_manifest(ws)
            self.assertEqual(manifest["plan_count"], 1)
            return manifest["plans"][0]

    # --- Case 1: forge -> forge_invariant ---
    def test_required_engine_forge_resolves_to_forge_invariant(self):
        """An unknown attack_class with required_engine=forge must NOT be
        needs_human; the planner must fall back to forge_invariant."""
        row = self._make_unknown_row("EXOTIC-001", "forge")
        plan = self._plan_single_row(row)
        self.assertEqual(plan["harness_family"], "forge_invariant",
                         "required_engine=forge must map to forge_invariant, "
                         "not needs_human")
        self.assertIn("required_engine", plan["reason"].lower(),
                      "reason must mention required_engine fallback path")

    # --- Case 1b: forge_invariant explicit value ---
    def test_required_engine_forge_invariant_explicit(self):
        row = self._make_unknown_row("EXOTIC-001B", "forge_invariant")
        plan = self._plan_single_row(row)
        self.assertEqual(plan["harness_family"], "forge_invariant")

    # --- Case 2: go -> cargo_unit_test (Go/DLT family) ---
    def test_required_engine_go_resolves_to_cargo_unit_test(self):
        """An unknown attack_class with required_engine=go must fall back to
        cargo_unit_test (the Go/DLT harness family), not needs_human."""
        row = self._make_unknown_row("EXOTIC-002", "go")
        plan = self._plan_single_row(row)
        self.assertEqual(plan["harness_family"], "cargo_unit_test",
                         "required_engine=go must map to cargo_unit_test, "
                         "not needs_human")
        self.assertIn("required_engine", plan["reason"].lower())

    # --- Case 3: cargo -> cargo_unit_test ---
    def test_required_engine_cargo_resolves_to_cargo_unit_test(self):
        """An unknown attack_class with required_engine=cargo must fall back to
        cargo_unit_test, not needs_human."""
        row = self._make_unknown_row("EXOTIC-003", "cargo")
        plan = self._plan_single_row(row)
        self.assertEqual(plan["harness_family"], "cargo_unit_test",
                         "required_engine=cargo must map to cargo_unit_test, "
                         "not needs_human")
        self.assertIn("required_engine", plan["reason"].lower())

    # --- Case 4: manual -> needs_human (no match, no useful required_engine) ---
    def test_required_engine_manual_still_yields_needs_human(self):
        """required_engine=manual provides no family signal; must still
        emit needs_human so the operator knows to intervene."""
        row = self._make_unknown_row("EXOTIC-004", "manual")
        plan = self._plan_single_row(row)
        self.assertEqual(plan["harness_family"], "needs_human",
                         "required_engine=manual must NOT bypass needs_human")

    # --- Case 5a: existing SC-segment path must not regress ---
    def test_sc_segment_still_takes_priority_over_required_engine(self):
        """A row with SC in its id segment must resolve via the SC branch
        (forge_invariant) regardless of required_engine — no regression."""
        row = self._make_unknown_row("EQ-001-SC", "forge")
        plan = self._plan_single_row(row)
        self.assertEqual(plan["harness_family"], "forge_invariant")

    # --- Case 5b: parity keyword wins over required_engine=forge ---
    def test_parity_keyword_wins_over_forge_required_engine(self):
        """When the statement contains 'parity', differential_fuzz wins
        over the required_engine=forge fallback — keyword path runs first."""
        row = self._make_unknown_row("EXOTIC-005", "forge")
        row["statement"] = "state-root parity divergence between oracle and impl"
        plan = self._plan_single_row(row)
        self.assertEqual(plan["harness_family"], "differential_fuzz",
                         "parity keyword in statement must win over "
                         "required_engine=forge fallback")


class TestPlannerSpeedupDemo(unittest.TestCase):
    """Speed-up demo: load KK's real base-azul ledger and assert the
    BASE-DLT-I01 plan would have surfaced engine_api_in_process directly,
    saving the cycles VV burned on broader-RPC harness attempts.

    We import the planner module in-process and call build_manifest()
    against a copied ledger, so this test runs even if the audits/
    workspace is read-only or absent (we read-only-load and rebuild from
    the on-disk JSON if present; otherwise skip).
    """

    BASE_LEDGER = Path("/Users/wolf/audits/base-azul/.auditooor/"
                       "invariant_ledger.json")

    def test_base_azul_fn7_row_surfaces_engine_api_in_process(self):
        if not self.BASE_LEDGER.exists():
            self.skipTest(f"base-azul ledger not present at "
                          f"{self.BASE_LEDGER}; speed-up demo skipped")
        # Load the real ledger
        ledger = json.loads(self.BASE_LEDGER.read_text())
        # Import the planner module (file with hyphen -> use spec_from_file)
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "invariant_harness_planner",
            ROOT / "tools" / "invariant-harness-planner.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Force include_all=True since the real BASE-DLT-I01 row is
        # already executed_clean (we are demonstrating "what the planner
        # would have surfaced before any work was done").
        manifest = mod.build_manifest(
            ledger, Path("/Users/wolf/audits/base-azul"),
            include_all=True)
        plans = {p["row_id"]: p for p in manifest["plans"]}
        self.assertIn("BASE-DLT-I01", plans,
                      "real base-azul ledger must contain BASE-DLT-I01 "
                      "(the FN7 invariant row)")
        self.assertEqual(plans["BASE-DLT-I01"]["harness_family"],
                         "engine_api_in_process",
                         "Speed-up demo: planner must point BASE-DLT-I01 "
                         "directly at engine_api_in_process, not "
                         "forge_invariant or live_check.")


if __name__ == "__main__":
    unittest.main()
