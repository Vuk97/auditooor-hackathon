"""Tests for cosmos_dynamic_harness_scaffold."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cosmos_dynamic_harness_scaffold",
    ROOT / "tools" / "cosmos_dynamic_harness_scaffold.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> tuple[Path, Path]:
    root = Path(tempfile.mkdtemp(prefix="cosmos_dynamic_scaffold_"))
    poc_dir = root / "poc-tests" / "candidate"
    poc_dir.mkdir(parents=True)
    (poc_dir / "poc_test.go").write_text(
        "package candidate\n\nfunc TestRuntimeMarkerCandidate(t *testing.T) {}\n",
        encoding="utf-8",
    )
    return root, poc_dir


def _request(network_claim: bool = False, validator_count: int = 2) -> mod.Request:
    ws, poc = _workspace()
    return mod.Request(
        workspace=ws,
        artifact_dir=ws / "artifacts",
        poc_dir=poc,
        cwd=poc,
        candidate_id="cand-1",
        target_repo="dydxprotocol/v4-chain",
        app_chain="dydx",
        claim_text="network-level chain halt" if network_claim else "single-validator state-machine proof",
        go_test_package="./x/clob/keeper",
        go_test_run="TestRuntimeMarkerCandidate",
        network_claim=network_claim,
        validator_count=validator_count,
        preset=mod.PRESET_DYDX,
    )


class CosmosDynamicHarnessScaffoldTests(unittest.TestCase):
    def test_single_validator_manifest_has_base_marker_contract(self):
        req = _request(network_claim=False, validator_count=1)
        manifest = mod.build_manifest(req)

        self.assertEqual(manifest["schema"], mod.SCHEMA)
        self.assertFalse(manifest["runtime_proof_claimed"])
        self.assertFalse(manifest["candidate"]["network_claim"])
        self.assertEqual(manifest["candidate"]["validator_count"], 1)
        self.assertEqual(
            manifest["runtime_marker_contract"]["required_events"],
            ["app_profile", "block_execution", "restart_check", "impact_assertion"],
        )
        self.assertIn("FinalizeBlock", manifest["rule_obligations"]["rule_19"]["required_path"])
        self.assertEqual(manifest["rule_obligations"]["rule_30"]["forbidden_backends"], ["MemDB"])

    def test_network_claim_requires_network_profile_marker(self):
        req = _request(network_claim=True, validator_count=4)
        manifest = mod.build_manifest(req)

        required_events = manifest["runtime_marker_contract"]["required_events"]
        self.assertTrue(manifest["candidate"]["network_claim"])
        self.assertIn("network_profile", required_events)
        self.assertEqual(manifest["candidate"]["validator_count"], 4)
        self.assertIn("--network-claim", manifest["execution_commands"]["phase_c_exec"])

    def test_write_bundle_emits_expected_files(self):
        req = _request(network_claim=True, validator_count=3)
        manifest = mod.build_manifest(req)
        files = mod.write_bundle(req, manifest)

        required_keys = {
            "manifest_json",
            "profile_json",
            "commands_json",
            "marker_template_json",
            "marker_template_jsonl",
            "tasks_markdown",
            "go_harness",
        }
        self.assertEqual(set(files), required_keys)
        for path in files.values():
            self.assertTrue(Path(path).is_file(), path)

        commands = json.loads(Path(files["commands_json"]).read_text(encoding="utf-8"))
        self.assertEqual(commands["schema"], mod.COMMANDS_SCHEMA)
        self.assertIn("cosmos-production-harness-plan.py", commands["commands"]["phase_a_plan"])
        self.assertIn("--require-runtime-markers", commands["commands"]["phase_c_exec"])
        self.assertIn("cosmos-production-harness-evidence-pack.py", commands["commands"]["phase_d_evidence_pack"])

        marker_lines = Path(files["marker_template_jsonl"]).read_text(encoding="utf-8").splitlines()
        self.assertTrue(marker_lines[0].startswith(mod.RUNTIME_EVENT_PREFIX))
        self.assertTrue(any('"event": "network_profile"' in line for line in marker_lines))

        tasks_text = Path(files["tasks_markdown"]).read_text(encoding="utf-8")
        self.assertIn("cosmos_production_harness_exec.json", tasks_text)
        self.assertIn("COSMOS_PRODUCTION_HARNESS_EVIDENCE_PACK.md", tasks_text)

    def test_render_go_harness_contains_three_production_profile_elements(self):
        # Single-validator harness must contain GoLevelDB (no MemDB), a real
        # FinalizeBlock+Commit driver, and a close+reopen restart sequence.
        req = _request(network_claim=False, validator_count=1)
        go_src = mod.render_go_harness(req)

        # (1) Real persistent backend - GoLevelDB, never MemDB.
        self.assertIn("dbm.NewGoLevelDB", go_src)
        self.assertNotIn("dbm.NewMemDB", go_src)
        self.assertNotIn("NewMemDB", go_src)

        # (2) FinalizeBlock + Commit block-execution driver.
        self.assertIn("FinalizeBlock", go_src)
        self.assertIn("Commit()", go_src)
        self.assertIn("func advanceBlock", go_src)

        # (3) Restart-survival sequence: close + reopen from same data dir.
        self.assertIn("func restartFromDisk", go_src)
        self.assertIn(".Close()", go_src)
        # reopen reuses dbm.NewGoLevelDB over the same dir (>=2 occurrences:
        # initial open + restart reopen).
        self.assertGreaterEqual(go_src.count("dbm.NewGoLevelDB"), 2)

        # No reflection / unsafe / private runtime-state surgery (Rule 30).
        for forbidden in ("reflect.NewAt", "unsafe.Pointer", "legacyLatestVersion"):
            self.assertNotIn(forbidden, go_src)

    def test_render_go_harness_network_claim_emits_multi_validator_signal(self):
        req = _request(network_claim=True, validator_count=4)
        go_src = mod.render_go_harness(req)
        # Explicit >=2-validator signal for the multi-validator preflight check.
        self.assertIn("numValidators = 4", go_src)
        self.assertIn("network_profile", go_src)

    def test_write_bundle_emits_go_harness_file_on_disk(self):
        req = _request(network_claim=False, validator_count=1)
        manifest = mod.build_manifest(req)
        files = mod.write_bundle(req, manifest)

        harness_path = Path(files["go_harness"])
        self.assertTrue(harness_path.is_file(), harness_path)
        self.assertEqual(harness_path.name, mod.GO_HARNESS_FILENAME)
        self.assertEqual(harness_path.parent.name, mod.GO_HARNESS_SUBDIR)

        go_src = harness_path.read_text(encoding="utf-8")
        self.assertIn("dbm.NewGoLevelDB", go_src)
        self.assertNotIn("dbm.NewMemDB", go_src)
        self.assertIn("FinalizeBlock", go_src)
        self.assertIn("restartFromDisk", go_src)

        # Manifest records the emitted harness and the gaps it satisfies.
        gh = manifest["go_harness"]
        self.assertTrue(gh["emitted"])
        self.assertEqual(gh["db_backend"], "GoLevelDB")
        self.assertEqual(
            set(gh["satisfies_preflight_gaps"]),
            {"real_db_backend", "finalize_block_commit", "restart_behavior"},
        )

    def test_emitted_harness_clears_three_preflight_gaps(self):
        # End-to-end: the emitted scaffold, scanned by the REAL Phase-A planner,
        # must move the verdict off needs_work and satisfy the 3 DB / block /
        # restart gaps that the Lane-5 probe found dead-ended.
        planner_path = ROOT / "tools" / "cosmos-production-harness-plan.py"
        planner_spec = importlib.util.spec_from_file_location(
            "cosmos_production_harness_plan", planner_path
        )
        planner = importlib.util.module_from_spec(planner_spec)
        planner_spec.loader.exec_module(planner)  # type: ignore[union-attr]

        req = _request(network_claim=False, validator_count=1)
        manifest = mod.build_manifest(req)
        mod.write_bundle(req, manifest)
        harness_dir = Path(manifest["go_harness"]["harness_dir"])

        plan = planner.build_plan(harness_dir, claim_text="", network_claim=False)
        self.assertEqual(plan["verdict"], "ready")
        by_id = {r["id"]: r["status"] for r in plan["requirements"]}
        self.assertEqual(by_id["real_db_backend"], "satisfied")
        self.assertEqual(by_id["finalize_block_commit"], "satisfied")
        self.assertEqual(by_id["restart_behavior"], "satisfied")
        self.assertEqual(by_id["no_private_state_injection"], "satisfied")

    def test_emitted_network_harness_clears_multi_validator_gap(self):
        planner_path = ROOT / "tools" / "cosmos-production-harness-plan.py"
        planner_spec = importlib.util.spec_from_file_location(
            "cosmos_production_harness_plan", planner_path
        )
        planner = importlib.util.module_from_spec(planner_spec)
        planner_spec.loader.exec_module(planner)  # type: ignore[union-attr]

        req = _request(network_claim=True, validator_count=4)
        manifest = mod.build_manifest(req)
        mod.write_bundle(req, manifest)
        harness_dir = Path(manifest["go_harness"]["harness_dir"])

        plan = planner.build_plan(
            harness_dir, claim_text="network-level chain halt", network_claim=True
        )
        self.assertEqual(plan["verdict"], "ready")
        by_id = {r["id"]: r["status"] for r in plan["requirements"]}
        self.assertEqual(by_id["multi_validator_if_claimed"], "satisfied")

    def test_scaffold_commands_point_poc_dir_at_emitted_harness(self):
        # The Phase-A/B/C commands the scaffold emits must point --poc-dir at
        # the generated Go harness package, not the audit-target source.
        req = _request(network_claim=False, validator_count=1)
        manifest = mod.build_manifest(req)
        harness_dir = str(mod._go_harness_dir(req))
        for phase in ("phase_a_plan", "phase_b_tasks", "phase_c_exec"):
            self.assertIn(harness_dir, manifest["execution_commands"][phase], phase)

    def test_cli_print_json_receipt(self):
        ws, poc = _workspace()
        artifact_dir = ws / "my-scaffold"
        rc = mod.main(
            [
                "--workspace",
                str(ws),
                "--poc-dir",
                str(poc),
                "--candidate-id",
                "cand-cli",
                "--preset",
                "dydx",
                "--go-test-run",
                "TestRuntimeMarkerCandidate",
                "--go-test-package",
                "./...",
                "--artifact-dir",
                str(artifact_dir),
                "--network-claim",
                "--validator-count",
                "2",
                "--print-json",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue((artifact_dir / "cosmos_dynamic_harness_manifest.json").is_file())

    def test_cli_dydx_preset_fills_go_test_defaults(self):
        ws, poc = _workspace()
        artifact_dir = ws / "my-scaffold-preset"
        rc = mod.main(
            [
                "--workspace",
                str(ws),
                "--poc-dir",
                str(poc),
                "--candidate-id",
                "cand-preset",
                "--preset",
                "dydx",
                "--artifact-dir",
                str(artifact_dir),
                "--print-json",
            ]
        )
        self.assertEqual(rc, 0)
        manifest = json.loads((artifact_dir / "cosmos_dynamic_harness_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["candidate"]["preset"], "dydx")
        self.assertIn("FinalizeBlock", manifest["rule_obligations"]["rule_19"]["required_path"])

    def test_invalid_network_validator_count_fails(self):
        req = _request(network_claim=True, validator_count=1)
        with self.assertRaisesRegex(ValueError, "network-claim requires --validator-count >= 2"):
            mod._validate(req)


if __name__ == "__main__":
    unittest.main()
