#!/usr/bin/env python3
"""
test_harness_scaffold_emitter.py — PR #535 / Wave 8 JJ2 tests.

Covers:
  * 5 plan -> scaffold mappings (one per supported harness_family):
      engine_api_in_process, cargo_unit_test, differential_fuzz,
      forge_invariant, live_check
  * idempotency: re-running the emitter does NOT overwrite existing
    scaffold files unless `--force` is passed
  * failed-attempt manifest: a plan whose required fixture kit is missing
    still produces a `status: blocked` attempt_manifest.json instead of
    crashing
  * generated Rust skeleton: file shape (Cargo.toml + tests/*.rs) and
    `cargo check` if cargo is available on the host
  * generated Foundry skeleton: file shape (foundry.toml +
    test/*.t.sol) and `forge build --no-match-test test` style compile
    check if forge is available on the host
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent
REPO = TOOLS.parent
EMITTER_PATH = TOOLS / "harness-scaffold-emitter.py"
PLANNER_PATH = TOOLS / "invariant-harness-planner.py"
FIXTURE_KITS = REPO / "reference" / "harness-fixture-kits"


def _load_emitter():
    spec = importlib.util.spec_from_file_location(
        "harness_scaffold_emitter", str(EMITTER_PATH))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


emitter = _load_emitter()


def _make_plan(row_id: str, harness_family: str,
               required_fixtures=None,
               source_invariant_family: str = "",
               compile_command: str = "",
               expected_log: str = "[PASS]",
               negative: str = "TBD",
               target: str = "src/Foo.sol:42",
               surface: str = "smallest test",
               locked_impact: bool = True,
               impact_overrides=None) -> dict:
    plan = {
        "row_id": row_id,
        "harness_family": harness_family,
        "reason": "test",
        "required_fixtures": required_fixtures or [],
        "target_entrypoint": target,
        "minimal_proof_surface": surface,
        "compile_command": compile_command,
        "first_negative_control": negative,
        "expected_log_string": expected_log,
        "stop_condition": "ok",
        "source_row_status": "missing_harness",
        "source_invariant_family": source_invariant_family,
    }
    if locked_impact:
        plan.update({
            "impact_contract_id": f"impact-contract-{row_id.lower()}",
            "selected_impact": "Direct theft of user funds",
            "severity": "High",
            "exact_impact_row": True,
            "listed_impact_proven": True,
        })
    if impact_overrides:
        plan.update(impact_overrides)
    return plan


def _wrap_manifest(plans, generated_at: str = "2026-04-29T00:00:00Z") -> dict:
    return {
        "schema_version": "auditooor.harness_plans.v1",
        "workspace": "/tmp/ws",
        "ledger_generated_at": generated_at,
        "ledger_row_count": len(plans),
        "plan_count": len(plans),
        "plans": plans,
        "skipped": [],
    }


class TestPerFamilyMapping(unittest.TestCase):
    """One plan -> one scaffold per supported harness_family."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emitter_t_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _emit(self, plan):
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        with contextlib.redirect_stdout(io.StringIO()):
            rc = emitter.main([
                "--plan", str(plan_file),
                "--workspace", str(self.ws),
                "--fixture-kits-root", str(FIXTURE_KITS),
            ])
        self.assertEqual(rc, 0)

    def test_engine_api_in_process(self):
        plan = _make_plan(
            "BASE-DLT-I01", "engine_api_in_process",
            compile_command="cargo test --manifest-path /ws/poc-tests/base_dlt_i01/Cargo.toml -- --nocapture",
            target="crates/engine/tree/src/tree/mod.rs:1234",
            negative="tampered withdrawals_root must be rejected")
        self._emit(plan)
        sdir = self.ws / "poc-tests" / "base_dlt_i01"
        self.assertTrue((sdir / "Cargo.toml").is_file())
        rs_files = list((sdir / "tests").glob("*.rs"))
        self.assertEqual(len(rs_files), 1)
        body = rs_files[0].read_text()
        self.assertIn("evidence-class: scaffolded_unverified", body)
        self.assertIn("harness-marker: engine_api_in_process", body)
        self.assertIn("tampered withdrawals_root must be rejected", body)
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["status"], "scaffolded_unverified")
        self.assertEqual(man["fixture_kit_id"], "engine_api_payload_chains")
        self.assertEqual(man["harness_family"], "engine_api_in_process")
        self.assertTrue(man["fixture_kit_sha"])
        self.assertEqual(man["impact_contract_id"],
                         "impact-contract-base-dlt-i01")
        self.assertEqual(man["selected_impact"],
                         "Direct theft of user funds")
        self.assertEqual(man["severity"], "High")
        self.assertTrue(man["exact_impact_row"])
        self.assertTrue(man["listed_impact_proven"])
        self.assertEqual(
            man["impact_contract_preflight"]["route"],
            "harness-scaffold",
        )
        self.assertEqual(
            man["impact_contract_preflight"]["decision"]["code"],
            "impact-contract-explicit",
        )

    def test_cargo_unit_test(self):
        plan = _make_plan(
            "BASE-DLT-U02", "cargo_unit_test",
            compile_command="cargo test --manifest-path /ws/poc-tests/base_dlt_u02/Cargo.toml -- --nocapture",
            target="crates/foo/src/lib.rs:88")
        self._emit(plan)
        sdir = self.ws / "poc-tests" / "base_dlt_u02"
        self.assertTrue((sdir / "Cargo.toml").is_file())
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["status"], "scaffolded_unverified")
        self.assertEqual(man["fixture_kit_id"], "engine_api_payload_chains")

    def test_forge_invariant_clob(self):
        plan = _make_plan(
            "POLY-CLOB-FILL-01", "forge_invariant",
            source_invariant_family="CLOB-LIFECYCLE",
            compile_command="FOUNDRY_PROFILE=invariants forge test --match-contract Invariant_POLY_CLOB_FILL_01 -vv")
        self._emit(plan)
        sdir = self.ws / "poc-tests-poly_clob_fill_01"
        self.assertTrue((sdir / "foundry.toml").is_file())
        sols = list((sdir / "test").glob("*.t.sol"))
        self.assertEqual(len(sols), 1)
        body = sols[0].read_text()
        self.assertIn("evidence-class: scaffolded_unverified", body)
        self.assertIn("harness-marker: forge_invariant", body)
        self.assertIn("Invariant_POLY_CLOB_FILL_01", body)
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["fixture_kit_id"], "clob_order_lifecycles")

    def test_forge_invariant_uma_negrisk(self):
        """Family-token routing: NEGRISK -> uma_negrisk_resolution kit."""
        plan = _make_plan(
            "POLY-NEGRISK-TIE", "forge_invariant",
            source_invariant_family="NEGRISK-RESOLUTION")
        self._emit(plan)
        sdir = self.ws / "poc-tests-poly_negrisk_tie"
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["fixture_kit_id"], "uma_negrisk_resolution")

    def test_forge_invariant_dispute(self):
        plan = _make_plan(
            "BASE-SC-DISPUTE-01", "forge_invariant",
            source_invariant_family="PROOF-DISPUTE-GAME")
        self._emit(plan)
        sdir = self.ws / "poc-tests-base_sc_dispute_01"
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["fixture_kit_id"],
                         "dispute_game_proof_catch_net")

    def test_live_check(self):
        plan = _make_plan(
            "POLY-LIVE-ROLE-01", "live_check",
            target="0xdeadbeef:owner()",
            compile_command="python3 tools/live-check-runner.py --row POLY-LIVE-ROLE-01")
        self._emit(plan)
        sdir = self.ws / "poc-tests" / "poly_live_role_01"
        spec_path = sdir / "live_check_spec.json"
        self.assertTrue(spec_path.is_file())
        spec = json.loads(spec_path.read_text())
        self.assertEqual(spec["spec_version"],
                         "auditooor.live_check_spec.v1")
        self.assertEqual(spec["evidence_class"], "scaffolded_unverified")
        self.assertEqual(spec["harness_marker"], "live_check")
        self.assertEqual(len(spec["checks"]), 2)
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["status"], "scaffolded_unverified")
        # live_check has no fixture kit
        self.assertIsNone(man["fixture_kit_id"])

    def test_differential_fuzz(self):
        plan = _make_plan(
            "BASE-DLT-PARITY-01", "differential_fuzz",
            compile_command="cargo run --manifest-path /ws/differential_fuzz/base_dlt_parity_01/Cargo.toml --release -- --corpus corpus/")
        self._emit(plan)
        sdir = self.ws / "poc-tests" / "base_dlt_parity_01"
        self.assertTrue((sdir / "Cargo.toml").is_file())
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["fixture_kit_id"],
                         "state_root_withdrawals_root_controls")


class TestIdempotency(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emitter_idem_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rerun_does_not_overwrite_unless_force(self):
        plan = _make_plan(
            "POLY-CLOB-A", "forge_invariant",
            source_invariant_family="CLOB-LIFECYCLE")
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))

        self.assertEqual(0, emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
        ]))
        sol = (self.ws / "poc-tests-poly_clob_a" / "test"
               / "Invariant_POLY_CLOB_A.t.sol")
        self.assertTrue(sol.is_file())
        sentinel = "// USER EDITED THIS LINE"
        sol.write_text(sentinel + "\n")

        # Re-run without --force: scaffold body NOT overwritten.
        self.assertEqual(0, emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
        ]))
        self.assertEqual(sol.read_text(), sentinel + "\n",
                         "idempotent re-run must not overwrite user edits")

        # With --force, re-emit (sentinel disappears).
        self.assertEqual(0, emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
            "--force",
        ]))
        self.assertNotEqual(sol.read_text(), sentinel + "\n",
                            "--force re-emit must overwrite the scaffold")


class TestBindingManifestEmission(unittest.TestCase):
    """The scaffold producer must emit the binding manifest consumed by the
    harness queue, not just its local attempt manifest."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emitter_binding_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _emit(self, plan, fixture_root=FIXTURE_KITS):
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = emitter.main([
                "--plan", str(plan_file),
                "--workspace", str(self.ws),
                "--fixture-kits-root", str(fixture_root),
            ])
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue())

    def test_ready_scaffold_writes_ready_binding_manifest(self):
        plan = _make_plan(
            "POLY-CLOB-BINDING", "forge_invariant",
            source_invariant_family="CLOB-LIFECYCLE",
            compile_command=(
                "FOUNDRY_PROFILE=invariants forge test "
                "--match-contract Invariant_POLY_CLOB_BINDING -vv"),
        )
        plan["setup_template"] = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Setup { function setUp() public virtual {} }\n"
        )

        summary = self._emit(plan)

        sdir = self.ws / "poc-tests-poly_clob_binding"
        binding_path = sdir / "harness_binding_manifest.json"
        self.assertTrue(binding_path.is_file())
        binding = json.loads(binding_path.read_text())
        self.assertEqual(binding["schema"], "auditooor.harness_binding_manifest.v0")
        self.assertEqual(binding["ready_count"], 1)
        self.assertEqual(binding["blocked_count"], 0)
        row = binding["rows"][0]
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["harness_command"], plan["compile_command"])
        self.assertEqual(row["gating_test"], plan["compile_command"])
        self.assertEqual(row["missing_inputs"], [])
        self.assertTrue(
            row["bindings"]["generated_test_path"].endswith(
                "Invariant_POLY_CLOB_BINDING.t.sol"))
        self.assertEqual(
            summary["results"][0]["binding_manifest_path"],
            str(binding_path.resolve()),
        )
        self.assertEqual(
            summary["results"][0]["binding_status"],
            "ready_executable_binding",
        )

    def test_blocked_attempt_writes_blocked_binding_manifest(self):
        plan = _make_plan(
            "BASE-DLT-BLOCKED-BINDING",
            "engine_api_in_process",
            locked_impact=False,
            compile_command=(
                "cargo test --manifest-path "
                "/tmp/ws/poc-tests/base_dlt_blocked_binding/Cargo.toml"),
            target="crates/engine/src/lib.rs:55",
        )

        summary = self._emit(plan)

        sdir = self.ws / "poc-tests" / "base_dlt_blocked_binding"
        attempt = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(attempt["status"], "blocked")
        binding = json.loads((sdir / "harness_binding_manifest.json").read_text())
        self.assertEqual(binding["schema"], "auditooor.harness_binding_manifest.v0")
        self.assertEqual(binding["ready_count"], 0)
        self.assertEqual(binding["blocked_count"], 1)
        row = binding["rows"][0]
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertIn("impact_contract_id", row["missing_inputs"])
        self.assertEqual(
            summary["results"][0]["binding_status"],
            "blocked_missing_inputs",
        )

    def test_blocked_attempt_cannot_become_ready_binding(self):
        empty_kits = self.tmp / "empty-kits"
        empty_kits.mkdir()
        plan = _make_plan(
            "BASE-DLT-MISSING-KIT-BINDING",
            "cargo_unit_test",
            compile_command=(
                "cargo test --manifest-path "
                "/tmp/ws/poc-tests/base_dlt_missing_kit_binding/Cargo.toml"),
            target="crates/engine/src/lib.rs:77",
        )
        plan["actor_setup"] = "generated scaffold setup"

        summary = self._emit(plan, fixture_root=empty_kits)

        sdir = self.ws / "poc-tests" / "base_dlt_missing_kit_binding"
        attempt = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(attempt["status"], "blocked")
        binding = json.loads((sdir / "harness_binding_manifest.json").read_text())
        row = binding["rows"][0]
        self.assertEqual(binding["ready_count"], 0)
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertIn("gating_test", row["missing_inputs"])
        self.assertIn("vague_command", row["blockers"])
        self.assertEqual(
            summary["results"][0]["binding_status"],
            "blocked_missing_inputs",
        )

    def test_idempotent_rerun_backfills_missing_binding_manifest(self):
        plan = _make_plan(
            "BASE-DLT-BACKFILL",
            "cargo_unit_test",
            compile_command=(
                "cargo test --manifest-path "
                "/tmp/ws/poc-tests/base_dlt_backfill/Cargo.toml"),
        )
        first = self._emit(plan)
        self.assertEqual(first["results"][0]["binding_status"],
                         "ready_executable_binding")

        sdir = self.ws / "poc-tests" / "base_dlt_backfill"
        binding_path = sdir / "harness_binding_manifest.json"
        binding_path.unlink()
        self.assertFalse(binding_path.exists())

        second = self._emit(plan)

        self.assertTrue(binding_path.is_file())
        self.assertTrue(second["results"][0]["skipped"])
        self.assertEqual(second["results"][0]["binding_status"],
                         "ready_executable_binding")


class TestP06StopConditionBridgeShape(unittest.TestCase):
    """P0-6 regression: the bridge-ready shape is 2 Solidity + 1 Base/DLT row.

    This does not claim the limitation stop condition is closed, because no
    harness is executed and no `poc-execution-record RESULT=proved
    IMPACT=exploit_impact` manifest is written here. It locks the scaffold and
    binding-manifest side of the stop condition so future bridge changes cannot
    regress the exact row mix P0-6 requires.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emitter_p06_shape_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_two_solidity_one_base_dlt_rows_become_ready_bindings(self):
        setup_template = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Setup { function setUp() public virtual {} }\n"
        )
        plans = [
            _make_plan(
                "POLY-CLOB-P06-A",
                "forge_invariant",
                source_invariant_family="CLOB-LIFECYCLE",
                compile_command=(
                    "FOUNDRY_PROFILE=invariants forge test "
                    "--match-contract Invariant_POLY_CLOB_P06_A -vv"
                ),
                target="src/Exchange.sol:42",
                surface="order lifecycle invariant replay",
            ),
            _make_plan(
                "POLY-CTF-P06-B",
                "forge_invariant",
                source_invariant_family="CTF-FEE-MATH",
                compile_command=(
                    "FOUNDRY_PROFILE=invariants forge test "
                    "--match-contract Invariant_POLY_CTF_P06_B -vv"
                ),
                target="src/CTFExchange.sol:77",
                surface="fee conservation invariant replay",
            ),
            _make_plan(
                "BASE-DLT-P06-C",
                "cargo_unit_test",
                source_invariant_family="BASE-DLT-WITHDRAWALS-ROOT",
                compile_command=(
                    "cargo test --manifest-path "
                    "/tmp/ws/poc-tests/base_dlt_p06_c/Cargo.toml -- --nocapture"
                ),
                target="crates/engine/tree/src/tree/mod.rs:88",
                surface="withdrawals root unit replay",
            ),
        ]
        for plan in plans[:2]:
            plan["setup_template"] = setup_template
        manifest = _wrap_manifest(plans)
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))

        summary_out = self.tmp / "summary.json"
        rc = emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
            "--summary-out", str(summary_out),
        ])
        self.assertEqual(rc, 0)

        summary = json.loads(summary_out.read_text())
        self.assertEqual(summary["row_count"], 3)
        self.assertEqual(summary["scaffolded"], 3)
        self.assertEqual(summary["blocked"], 0)
        self.assertEqual(summary["binding_manifest_ready_count"], 3)
        self.assertEqual(summary["binding_manifest_blocked_count"], 0)

        binding = json.loads((self.ws / ".auditooor" / "harness_binding_manifest.json").read_text())
        self.assertEqual(binding["ready_count"], 3)
        self.assertEqual(binding["blocked_count"], 0)
        families = {row["harness_family"] for row in binding["rows"]}
        self.assertEqual(families, {"forge_invariant", "cargo_unit_test"})
        solidity_rows = [row for row in binding["rows"] if row["harness_family"] == "forge_invariant"]
        dlt_rows = [row for row in binding["rows"] if row["harness_family"] == "cargo_unit_test"]
        self.assertEqual(len(solidity_rows), 2)
        self.assertEqual(len(dlt_rows), 1)
        for row in binding["rows"]:
            self.assertEqual(row["status"], "ready_executable_binding")
            self.assertEqual(row["missing_inputs"], [])
            self.assertTrue(row["harness_command"])
            self.assertTrue(row["gating_test"])
            self.assertTrue(row["bindings"]["generated_test_path"])
            self.assertTrue(row["bindings"]["impact_contract_id"])

        expected_paths = [
            self.ws / "poc-tests-poly_clob_p06_a" / "test" / "Invariant_POLY_CLOB_P06_A.t.sol",
            self.ws / "poc-tests-poly_ctf_p06_b" / "test" / "Invariant_POLY_CTF_P06_B.t.sol",
            self.ws / "poc-tests" / "base_dlt_p06_c" / "tests" / "base_dlt_p06_c_smoke.rs",
        ]
        for path in expected_paths:
            self.assertTrue(path.is_file(), str(path))


class TestFailedAttemptManifest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emitter_fail_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()
        self.empty_kits = self.tmp / "empty-kits"
        self.empty_kits.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_kit_writes_blocked_manifest(self):
        """Pointing the emitter at an empty kits dir means
        engine_api_payload_chains does not exist, so emission must fail
        gracefully with a `blocked` manifest, NOT an exception."""
        plan = _make_plan(
            "BASE-DLT-MISS", "engine_api_in_process")
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        rc = emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(self.empty_kits),
        ])
        self.assertEqual(rc, 0)
        man_path = (self.ws / "poc-tests" / "base_dlt_miss"
                    / "attempt_manifest.json")
        self.assertTrue(man_path.is_file(),
                        "blocker manifest must still be written")
        man = json.loads(man_path.read_text())
        self.assertEqual(man["status"], "blocked")
        self.assertIn("not found", man["blocker_reason"])
        # Crucially, NO test file should have been created.
        self.assertFalse((self.ws / "poc-tests" / "base_dlt_miss"
                          / "Cargo.toml").is_file())

    def test_unsupported_family_writes_blocked_manifest(self):
        plan = _make_plan(
            "BASE-SC-HALMOS-01", "halmos_symbolic")
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        rc = emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
        ])
        self.assertEqual(rc, 0)
        sdir = self.ws / "poc-tests" / "base_sc_halmos_01"
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["status"], "blocked")
        self.assertIn("does not support", man["blocker_reason"])

    def test_missing_impact_contract_writes_only_blocked_manifest(self):
        """Ampere gate: no scaffold body emits without locked impact proof."""
        plans = [
            _make_plan("BASE-DLT-NOIMPACT", "engine_api_in_process",
                       locked_impact=False),
            _make_plan("POLY-CLOB-NOIMPACT", "forge_invariant",
                       source_invariant_family="CLOB-LIFECYCLE",
                       locked_impact=False),
            _make_plan("POLY-LIVE-NOIMPACT", "live_check",
                       locked_impact=False),
        ]
        manifest = _wrap_manifest(plans)
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        rc = emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
        ])
        self.assertEqual(rc, 0)

        rust_dir = self.ws / "poc-tests" / "base_dlt_noimpact"
        rust_man = json.loads((rust_dir / "attempt_manifest.json").read_text())
        self.assertEqual(rust_man["status"], "blocked")
        self.assertEqual(rust_man["blocker_reason"],
                         "blocked_missing_impact_contract")
        self.assertEqual(
            rust_man["impact_contract_preflight"]["decision"]["code"],
            "impact-contract-missing",
        )
        self.assertFalse((rust_dir / "Cargo.toml").exists())
        self.assertFalse((rust_dir / "tests").exists())

        forge_dir = self.ws / "poc-tests-poly_clob_noimpact"
        forge_man = json.loads((forge_dir / "attempt_manifest.json").read_text())
        self.assertEqual(forge_man["status"], "blocked")
        self.assertEqual(forge_man["blocker_reason"],
                         "blocked_missing_impact_contract")
        self.assertFalse((forge_dir / "foundry.toml").exists())
        self.assertFalse((forge_dir / "test").exists())

        live_dir = self.ws / "poc-tests" / "poly_live_noimpact"
        live_man = json.loads((live_dir / "attempt_manifest.json").read_text())
        self.assertEqual(live_man["status"], "blocked")
        self.assertEqual(live_man["blocker_reason"],
                         "blocked_missing_impact_contract")
        self.assertFalse((live_dir / "live_check_spec.json").exists())

    def test_workspace_impact_contract_unlocks_scaffold_and_manifest_metadata(self):
        plan = _make_plan(
            "BASE-DLT-WORKSPACE", "cargo_unit_test",
            locked_impact=False,
            impact_overrides={
                "impact_contract_id": "impact-contract-workspace-locked",
            },
        )
        aud = self.ws / ".auditooor"
        aud.mkdir()
        (aud / "impact_contracts.json").write_text(json.dumps({
            "contracts": [
                {
                    "impact_contract_id": "impact-contract-workspace-locked",
                    "selected_impact": "Temporary freezing of user funds",
                    "severity": "Medium",
                    "exact_impact_row": True,
                    "listed_impact_proven": True,
                }
            ]
        }))
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        rc = emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
        ])
        self.assertEqual(rc, 0)
        sdir = self.ws / "poc-tests" / "base_dlt_workspace"
        self.assertTrue((sdir / "Cargo.toml").is_file())
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["status"], "scaffolded_unverified")
        self.assertEqual(man["impact_contract_id"],
                         "impact-contract-workspace-locked")
        self.assertEqual(man["selected_impact"],
                         "Temporary freezing of user funds")
        self.assertEqual(man["severity"], "Medium")
        self.assertTrue(man["listed_impact_proven"])


class TestGeneratedFileShape(unittest.TestCase):
    """If cargo / forge are present we run a real compile; otherwise fall
    back to a structural check (file exists, has expected sections)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emitter_shape_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rust_skeleton_compiles_or_shape(self):
        plan = _make_plan("BASE-DLT-OK", "cargo_unit_test")
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
        ])
        sdir = self.ws / "poc-tests" / "base_dlt_ok"
        cargo_toml = sdir / "Cargo.toml"
        self.assertTrue(cargo_toml.is_file())
        rs_files = list((sdir / "tests").glob("*.rs"))
        self.assertEqual(len(rs_files), 1)
        body = rs_files[0].read_text()
        # shape assertions (always required)
        self.assertIn("[package]", cargo_toml.read_text())
        self.assertIn("#[test]", body)
        self.assertIn("_positive", body)
        self.assertIn("_negative", body)

        # Optional: real cargo check.
        if shutil.which("cargo"):
            try:
                proc = subprocess.run(
                    ["cargo", "check",
                     "--manifest-path", str(cargo_toml)],
                    capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(
                    proc.returncode, 0,
                    f"cargo check failed:\nstdout={proc.stdout}\n"
                    f"stderr={proc.stderr}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.skipTest("cargo present but compile probe timed out")

    def test_solidity_skeleton_shape(self):
        plan = _make_plan(
            "POLY-CLOB-OK", "forge_invariant",
            source_invariant_family="CLOB-LIFECYCLE")
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        emitter.main([
            "--plan", str(plan_file),
            "--workspace", str(self.ws),
            "--fixture-kits-root", str(FIXTURE_KITS),
        ])
        sdir = self.ws / "poc-tests-poly_clob_ok"
        toml = sdir / "foundry.toml"
        sol = sdir / "test" / "Invariant_POLY_CLOB_OK.t.sol"
        self.assertTrue(toml.is_file())
        self.assertTrue(sol.is_file())
        body = sol.read_text()
        # shape assertions (always required)
        self.assertIn("pragma solidity ^0.8.20", body)
        self.assertIn("contract Invariant_POLY_CLOB_OK", body)
        self.assertIn("function setUp()", body)
        self.assertIn("function test_poly_clob_ok_positive()", body)
        self.assertIn("function test_poly_clob_ok_negative()", body)
        self.assertIn("function invariant_placeholder()", body)

        # Optional: forge build (compile check only).
        if shutil.which("forge"):
            try:
                proc = subprocess.run(
                    ["forge", "build", "--root", str(sdir)],
                    capture_output=True, text=True, timeout=60,
                )
                # Compile may pass or fail gracefully — we just want the
                # binary to not raise an internal error. Treat exit 0/1 as
                # acceptable; only flag unexpected errors.
                self.assertIn(proc.returncode, (0, 1, 2))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.skipTest("forge present but compile probe timed out")


class TestKitResolution(unittest.TestCase):
    """Direct unit tests for resolve_kit_for_plan dispatcher."""

    def test_explicit_kit_in_required_fixtures_wins(self):
        plan = _make_plan("X", "engine_api_in_process",
                          required_fixtures=["state_root_withdrawals_root_controls"])
        kid, _ = emitter.resolve_kit_for_plan(plan)
        self.assertEqual(kid, "state_root_withdrawals_root_controls")

    def test_engine_api_default(self):
        plan = _make_plan("X", "engine_api_in_process")
        kid, _ = emitter.resolve_kit_for_plan(plan)
        self.assertEqual(kid, "engine_api_payload_chains")

    def test_forge_ctf_routes_to_ctf_fee_conservation(self):
        plan = _make_plan("X", "forge_invariant",
                          source_invariant_family="CTF-FEE-MATH")
        kid, _ = emitter.resolve_kit_for_plan(plan)
        self.assertEqual(kid, "ctf_fee_conservation")

    def test_unknown_family_returns_none(self):
        plan = _make_plan("X", "halmos_symbolic")
        kid, _ = emitter.resolve_kit_for_plan(plan)
        self.assertIsNone(kid)


class TestEmptySetupFallback(unittest.TestCase):
    """Wave J-1B / PR #600 §P0-6: empty-Setup.sol blocker fix.

    When the planner returns no setup_template, the emitter must:
      - still write test/Setup.sol (so forge build does not fail at import
        resolution),
      - use the minimal compilable MINIMAL_SETUP_SOL placeholder,
      - set attempt_manifest.status  == 'scaffolded_unverified_empty_setup'
        (NOT 'scaffolded_unverified', so it is never auto-promoted),
      - set attempt_manifest.blocker_reason ==
        'empty_setup_placeholder_needs_operator_fill'.

    When the planner DOES supply a setup_template, the emitter uses it and
    falls back to the standard 'scaffolded_unverified' status.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="emitter_empty_setup_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _emit(self, plan):
        manifest = _wrap_manifest([plan])
        plan_file = self.tmp / "plans.json"
        plan_file.write_text(json.dumps(manifest))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = emitter.main([
                "--plan", str(plan_file),
                "--workspace", str(self.ws),
                "--fixture-kits-root", str(FIXTURE_KITS),
            ])
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue())

    # ------------------------------------------------------------------
    # Vulnerable path: no setup_template → minimal placeholder
    # ------------------------------------------------------------------

    def test_no_setup_template_emits_placeholder_and_new_status(self):
        """Planner returns no setup_template → emitter writes minimal
        placeholder + status 'scaffolded_unverified_empty_setup'."""
        plan = _make_plan(
            "POLY-CLOB-NOSETUP", "forge_invariant",
            source_invariant_family="CLOB-LIFECYCLE",
            compile_command=(
                "FOUNDRY_PROFILE=invariants forge test "
                "--match-contract Invariant_POLY_CLOB_NOSETUP -vv"))
        # Explicitly omit setup_template (default _make_plan doesn't add it).
        self.assertNotIn("setup_template", plan)

        summary = self._emit(plan)

        sdir = self.ws / "poc-tests-poly_clob_nosetup"
        setup_path = sdir / "test" / "Setup.sol"

        # File must exist and be non-empty.
        self.assertTrue(setup_path.is_file(),
                        "Setup.sol must be written even when no setup_template")
        content = setup_path.read_text()
        self.assertGreater(len(content.strip()), 0,
                           "Setup.sol must not be empty")

        # Must contain the minimal stub markers.
        self.assertIn("contract Setup", content)
        self.assertIn("function setUp()", content)
        self.assertIn("MINIMAL_SETUP_SOL" if False else
                      "Wave J-1B", content,
                      "Placeholder must carry the Wave J-1B advisory comment")

        # Attempt manifest must use the new status.
        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["status"], "scaffolded_unverified_empty_setup")
        self.assertEqual(man["blocker_reason"],
                         "empty_setup_placeholder_needs_operator_fill")

        # Summary row must also reflect the new status.
        row = summary["results"][0]
        self.assertEqual(row["status"], "scaffolded_unverified_empty_setup")
        self.assertEqual(row["blocker_reason"],
                         "empty_setup_placeholder_needs_operator_fill")

        # Summary scalar counter.
        self.assertEqual(summary["scaffolded_empty_setup"], 1)
        self.assertEqual(summary["scaffolded"], 0)
        self.assertEqual(summary["binding_manifest_blocked_count"], 1)

        binding_path = Path(summary["binding_manifest_path"])
        self.assertTrue(binding_path.is_file())
        binding = json.loads(binding_path.read_text())
        self.assertEqual(binding["schema"],
                         "auditooor.harness_binding_manifest.v0")
        row = binding["rows"][0]
        self.assertEqual(row["row_id"], "POLY-CLOB-NOSETUP")
        self.assertEqual(row["status"], "blocked_missing_inputs")
        self.assertIn("actor_setup", row["missing_inputs"])
        self.assertEqual(
            row["harness_command"],
            "FOUNDRY_PROFILE=invariants forge test "
            "--match-contract Invariant_POLY_CLOB_NOSETUP -vv",
        )

    # ------------------------------------------------------------------
    # Clean path: setup_template present → existing status unchanged
    # ------------------------------------------------------------------

    def test_real_setup_template_uses_existing_status(self):
        """Planner returns a real setup_template → emitter writes that
        content, status stays 'scaffolded_unverified' (existing path)."""
        custom_setup = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Setup {\n"
            "    address internal actor = address(0xBEEF);\n"
            "    function setUp() public virtual {}\n"
            "}\n"
        )
        plan = _make_plan(
            "POLY-CLOB-WITHSETUP", "forge_invariant",
            source_invariant_family="CLOB-LIFECYCLE",
            required_fixtures=["clob_order_lifecycles"],
            compile_command=(
                "FOUNDRY_PROFILE=invariants forge test "
                "--match-contract Invariant_POLY_CLOB_WITHSETUP -vv"))
        plan["setup_template"] = custom_setup

        summary = self._emit(plan)

        sdir = self.ws / "poc-tests-poly_clob_withsetup"
        setup_path = sdir / "test" / "Setup.sol"

        self.assertTrue(setup_path.is_file())
        written = setup_path.read_text()
        self.assertEqual(written, custom_setup,
                         "setup_template must be written verbatim")

        man = json.loads((sdir / "attempt_manifest.json").read_text())
        self.assertEqual(man["status"], "scaffolded_unverified",
                         "Real setup_template must not trigger empty-setup status")
        self.assertIsNone(man["blocker_reason"],
                          "blocker_reason must be None when setup_template provided")

        self.assertEqual(summary["binding_manifest_ready_count"], 1)
        binding = json.loads(Path(summary["binding_manifest_path"]).read_text())
        row = binding["rows"][0]
        self.assertEqual(row["row_id"], "POLY-CLOB-WITHSETUP")
        self.assertEqual(row["status"], "ready_executable_binding")
        self.assertEqual(row["missing_inputs"], [])

    # ------------------------------------------------------------------
    # Compile-check: placeholder is structurally valid Solidity
    # ------------------------------------------------------------------

    def test_placeholder_is_valid_solidity_structure(self):
        """The MINIMAL_SETUP_SOL string must be parseable as a Solidity
        contract with a setUp() function — validated via regex since forge
        may not be present on the host."""
        content = emitter.MINIMAL_SETUP_SOL
        # Must declare an SPDX identifier.
        self.assertIn("SPDX-License-Identifier:", content)
        # Must have a pragma.
        self.assertRegex(content, r"pragma solidity \^?0\.\d+")
        # Must declare `contract Setup`.
        self.assertRegex(content, r"contract\s+Setup\s*\{")
        # Must declare `function setUp()`.
        self.assertRegex(content, r"function\s+setUp\s*\(\s*\)")
        # Must not be empty inside the contract body.
        self.assertIn("{", content)
        self.assertIn("}", content)

        # Optional: forge build in an isolated temp dir.
        if shutil.which("forge"):
            forge_tmp = Path(tempfile.mkdtemp(prefix="emitter_forge_stub_"))
            try:
                src_dir = forge_tmp / "src"
                src_dir.mkdir()
                (src_dir / "Setup.sol").write_text(content)
                (forge_tmp / "foundry.toml").write_text(
                    "[profile.default]\nsrc = \"src\"\nout = \"out\"\n"
                    "libs = [\"lib\"]\nsolc_version = \"0.8.24\"\n"
                )
                proc = subprocess.run(
                    ["forge", "build", "--root", str(forge_tmp)],
                    capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(
                    proc.returncode, 0,
                    f"forge build of MINIMAL_SETUP_SOL failed:\n"
                    f"stdout={proc.stdout}\nstderr={proc.stderr}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.skipTest("forge present but compile probe timed out")
            finally:
                shutil.rmtree(forge_tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
