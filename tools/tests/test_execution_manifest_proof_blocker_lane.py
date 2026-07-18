from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "execution-manifest-proof-blocker-lane.py"


def _import():
    spec = importlib.util.spec_from_file_location("execution_manifest_proof_blocker_lane_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _proved_manifest(candidate: str = "proved-case") -> dict[str, object]:
    return {
        "candidate_id": candidate,
        "final_result": "proved",
        "impact_assertion": "exploit_impact",
        "evidence_class": "executed_with_manifest",
        "commands_attempted": [{"command": "forge test --match-test testExploitImpact", "status": "pass", "exit_code": 0}],
    }


def _fixtures(ws: Path) -> None:
    aud = ws / ".auditooor"
    _write_json(
        aud / "pr560_worker_fm_execution_manifest_gate.json",
        {
            "before_after_counts": {
                "execution_manifest_gate": {
                    "after": {"manifest_count": 2, "proof_counted": 1},
                    "before": {"manifest_count": 2, "proof_counted": 0},
                }
            }
        },
    )
    _write_json(
        aud / "execution_proof_command_manifest.json",
        {
            "rows": [
                {
                    "task_id": "safe",
                    "proof_kind": "harness_plan_inventory",
                    "readiness": "safe_to_execute",
                },
                {
                    "task_id": "bind-me",
                    "proof_kind": "forge_execution",
                    "readiness": "needs_binding",
                    "safety_blocks": ["unresolved_placeholders"],
                    "unresolved_placeholders": ["<generated-test>"],
                    "proof_recording_command_template": "make poc-execution-record WS=/tmp/ws BRIEF=<brief> RESULT=needs_human IMPACT=unknown",
                },
            ]
        },
    )
    _write_json(
        aud / "pr560_worker_ev_bridge_finalization_closure.json",
        {"before_after_counts": {"missing_poc_execution_manifest": {"before": 1, "after": 0}}},
    )
    _write_json(
        aud / "pr560_worker_fg_proof_live_closure.json",
        {"before_after_counts": {"impact_proof": {"listed_impact_not_proven": 1}}},
    )
    _write_json(
        ws / "poc_execution" / "imo-critical-access-control-01" / "execution_manifest.json",
        {
            "candidate_id": "imo-critical-access-control-01",
            "final_result": "blocked_path",
            "impact_assertion": "not_demonstrated",
            "commands_attempted": [{"status": "fail", "exit_code": 2}],
        },
    )
    _write_json(
        ws / "poc_execution" / "proved-case" / "execution_manifest.json",
        _proved_manifest(),
    )


class ExecutionManifestProofBlockerLaneTests(unittest.TestCase):
    def test_build_payload_keeps_proof_boundary_and_groups_blockers(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["poc_execution_manifest_count"], 2)
        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 1)
        self.assertEqual(payload["after_counts"]["terminal_poc_execution_manifest_blockers"], 1)
        self.assertEqual(payload["after_counts"]["terminal_command_task_blockers"], 1)
        self.assertIn("final_result_blocked_path", payload["after_counts"]["terminal_blocker_counts"])
        candidate = payload["closure_candidates"][0]
        self.assertEqual(candidate["evidence_class"], "executed_with_manifest")
        self.assertEqual(candidate["passing_command_count"], 1)
        self.assertEqual(candidate["command_status_counts"], {"pass": 1})
        self.assertFalse(payload["promotion_allowed"])

    def test_claimed_proved_manifest_without_canonical_evidence_class_is_blocked(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["evidence_class"] = "generated_hypothesis"
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertIn("evidence_class_executed_with_manifest", rows["proved-case"]["terminal_blockers"])
        self.assertFalse(rows["proved-case"]["closure_candidate"])

    def test_claimed_proved_manifest_missing_evidence_class_is_blocked(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            del manifest["evidence_class"]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertEqual(rows["proved-case"]["evidence_class"], "missing")
        self.assertIn("evidence_class_executed_with_manifest", rows["proved-case"]["terminal_blockers"])

    def test_recorded_without_execution_command_is_blocked(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [
                {"command": "forge test", "status": "recorded_without_execution", "exit_code": None}
            ]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertEqual(rows["proved-case"]["passing_command_count"], 0)
        self.assertEqual(rows["proved-case"]["command_status_counts"], {"recorded_without_execution": 1})
        self.assertIn("commands_attempted_pass_exit_0", rows["proved-case"]["terminal_blockers"])

    def test_claimed_proved_manifest_with_failed_command_is_blocked(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "fail", "exit_code": 1}]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertEqual(rows["proved-case"]["passing_command_count"], 0)
        self.assertIn("commands_attempted_pass_exit_0", rows["proved-case"]["terminal_blockers"])
        self.assertIn("command_exit_nonzero", rows["proved-case"]["terminal_blockers"])

    def test_claimed_proved_manifest_with_unstructured_command_is_blocked(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = ["forge test --match-test testExploitImpact"]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertEqual(rows["proved-case"]["command_status_counts"], {"unstructured": 1})
        self.assertIn("commands_attempted_structured", rows["proved-case"]["terminal_blockers"])
        self.assertIn("commands_attempted_pass_exit_0", rows["proved-case"]["terminal_blockers"])

    def test_mixed_commands_with_one_pass_exit_zero_is_closure_candidate(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [
                {"command": "forge test", "status": "fail", "exit_code": 1},
                {"command": "forge test", "status": "pass", "exit_code": 0},
            ]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 1)
        candidate = payload["closure_candidates"][0]
        self.assertEqual(candidate["passing_command_count"], 1)
        self.assertEqual(candidate["command_status_counts"], {"fail": 1, "pass": 1})
        self.assertNotIn("command_exit_nonzero", candidate["terminal_blockers"])

    def test_string_exit_zero_is_closure_candidate(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "pass", "exit_code": "0"}]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 1)
        self.assertEqual(payload["closure_candidates"][0]["passing_command_count"], 1)

    def test_empty_command_text_blocks_even_with_pass_exit_zero(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "  ", "status": "pass", "exit_code": 0}]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertEqual(rows["proved-case"]["passing_command_count"], 0)
        self.assertIn("commands_attempted_nonempty_command", rows["proved-case"]["terminal_blockers"])
        self.assertIn("commands_attempted_pass_exit_0", rows["proved-case"]["terminal_blockers"])

    def test_missing_exit_code_blocks_even_with_pass_status(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "pass"}]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertEqual(rows["proved-case"]["passing_command_count"], 0)
        self.assertEqual(rows["proved-case"]["missing_exit_code_count"], 1)
        self.assertIn("commands_attempted_pass_exit_0", rows["proved-case"]["terminal_blockers"])
        self.assertIn("command_exit_code_missing", rows["proved-case"]["terminal_blockers"])

    def test_bool_exit_code_does_not_count_as_zero(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "pass", "exit_code": False}]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertEqual(rows["proved-case"]["passing_command_count"], 0)
        self.assertEqual(rows["proved-case"]["bool_exit_code_count"], 1)
        self.assertIn("commands_attempted_pass_exit_0", rows["proved-case"]["terminal_blockers"])
        self.assertIn("command_exit_code_bool", rows["proved-case"]["terminal_blockers"])

    def test_nonnumeric_exit_code_blocks_without_crashing(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "fail", "exit_code": "not-a-number"}]
            _write_json(ws / "poc_execution" / "proved-case" / "execution_manifest.json", manifest)
            payload = mod.build_payload(ws)

        self.assertEqual(payload["after_counts"]["proved_exploit_impact_closure_candidates"], 0)
        rows = {row["candidate_id"]: row for row in payload["terminal_poc_execution_manifest_blockers"]}
        self.assertIn("command_exit_nonzero", rows["proved-case"]["terminal_blockers"])

    def test_write_family_artifacts(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _fixtures(ws)
            payload = mod.build_payload(ws)
            mod.write_family_artifacts(payload, ws / ".auditooor")
            self.assertTrue((ws / ".auditooor" / "execution_manifest_terminal_blockers_fi" / "access_control.json").is_file())
            self.assertTrue((ws / ".auditooor" / "execution_manifest_terminal_blockers_fi" / "task_forge_execution.json").is_file())
            self.assertTrue((ws / ".auditooor" / "execution_manifest_closure_candidates_fi" / "proved-case.json").is_file())


if __name__ == "__main__":
    unittest.main()
