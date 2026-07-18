from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-novel-vector-gen.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_novel_vector_gen", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanNovelVectorGenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory(prefix="hackerman-novel-vector-gen-")
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, body: str) -> Path:
        path = self.tag_dir / name
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return path

    _LOCAL_ACCESS = """
        schema_version: auditooor.hackerman_record.v1.1
        record_id: local:access-1
        source_audit_ref: prior:local-access-1
        target_domain: treasury
        target_language: solidity
        target_repo: example/vault
        target_component: Vault.setOperator
        function_shape:
          raw_signature: "function setOperator(address operator) external"
          shape_tags:
            - external-privileged-write
            - single-role-guard
        bug_class: missing-access-control
        attack_class: access-control-bypass
        attacker_role: arbitrary-user
        attacker_action_sequence: "Step 1: call the unprotected operator setter."
        required_preconditions:
          - setter is externally reachable
        impact_class: privilege-escalation
        impact_actor: arbitrary-user
        impact_dollar_class: non-financial
        fix_pattern: add onlyOwner
        fix_anti_pattern_avoided: unguarded operator setter
        severity_at_finding: high
        year: 2024
        cross_language_analogues: []
        related_records: []
        """

    _LOCAL_TARGET = """
        schema_version: auditooor.hackerman_record.v1.1
        record_id: local:rounding-2
        source_audit_ref: prior:local-rounding-2
        target_domain: treasury
        target_language: solidity
        target_repo: example/vault
        target_component: Treasury.withdrawFees
        function_shape:
          raw_signature: "function withdrawFees(address recipient, uint256 amount) external"
          shape_tags:
            - external-privileged-fund-move
            - single-role-guard
        bug_class: fee-rounding-leak
        attack_class: rounding-manipulation
        attacker_role: arbitrary-user
        attacker_action_sequence: "Step 1: skew fee accounting before admin withdrawal."
        required_preconditions:
          - internal fee accounting can drift
        impact_class: precision-loss
        impact_actor: treasury
        impact_dollar_class: "$1K-$10K"
        fix_pattern: reconcile fee accounting before withdrawal
        fix_anti_pattern_avoided: stale fee accumulator
        severity_at_finding: medium
        year: 2024
        cross_language_analogues: []
        related_records: []
        """

    _REMOTE_ANALOGUE = """
        schema_version: auditooor.hackerman_record.v1.1
        record_id: remote:drain-3
        source_audit_ref: prior:remote-drain-3
        target_domain: treasury
        target_language: solidity
        target_repo: peer/vault
        target_component: Treasury.withdrawFees
        function_shape:
          raw_signature: "function withdrawFees(address recipient, uint256 amount) external"
          shape_tags:
            - external-privileged-fund-move
            - single-role-guard
        bug_class: privileged-treasury-drain
        attack_class: privilege-escalation-fund-theft
        attacker_role: privileged
        attacker_action_sequence: "Step 1: as operator, drain treasury fees."
        required_preconditions:
          - caller holds the owner role
          - protocol funds are present in the treasury
        impact_class: theft
        impact_actor: protocol-treasury
        impact_dollar_class: "$100K-$1M"
        fix_pattern: timelock and separate treasury withdrawal authority
        fix_anti_pattern_avoided: instant operator treasury drain
        severity_at_finding: critical
        year: 2024
        cross_language_analogues: []
        related_records: []
        """

    _LOCAL_EXISTING_CLASS = """
        schema_version: auditooor.hackerman_record.v1.1
        record_id: local:drain-4
        source_audit_ref: prior:local-drain-4
        target_domain: treasury
        target_language: solidity
        target_repo: example/vault
        target_component: Treasury.emergencyDrain
        function_shape:
          raw_signature: "function emergencyDrain(address recipient, uint256 amount) external"
          shape_tags:
            - external-privileged-fund-move
            - single-role-guard
        bug_class: privileged-treasury-drain
        attack_class: privilege-escalation-fund-theft
        attacker_role: privileged
        attacker_action_sequence: "Step 1: as operator, drain treasury funds."
        required_preconditions:
          - caller holds the owner role
          - treasury holds protocol funds
        impact_class: theft
        impact_actor: protocol-treasury
        impact_dollar_class: "$100K-$1M"
        fix_pattern: timelock and multisig emergency drain
        fix_anti_pattern_avoided: instant privileged treasury drain
        severity_at_finding: high
        year: 2024
        cross_language_analogues: []
        related_records: []
        """

    def test_build_payload_emits_advisory_novel_vector(self) -> None:
        self._write("local_access.yaml", self._LOCAL_ACCESS)
        self._write("local_target.yaml", self._LOCAL_TARGET)
        self._write("remote_analogue.yaml", self._REMOTE_ANALOGUE)

        payload = self.tool.build_payload(self.tag_dir, limit=10)

        self.assertEqual(
            payload["schema"],
            "auditooor.hackerman_novel_vector_hypotheses.summary.v1",
        )
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["total_hypotheses"], 1)
        hypothesis = payload["hypotheses"][0]
        self.assertEqual(
            hypothesis["novel_attack_class"],
            "privilege-escalation-fund-theft",
        )
        self.assertEqual(hypothesis["target_repo"], "example/vault")
        self.assertEqual(hypothesis["target_component"], "Treasury.withdrawFees")
        self.assertEqual(
            hypothesis["nearest_analogue"]["record_id"],
            "remote:drain-3",
        )
        self.assertNotIn("submission_posture", hypothesis)
        self.assertTrue(hypothesis["proof_obligations"])
        self.assertIn(
            "state:privileged-caller-context",
            {
                item["value"]
                for item in hypothesis["preconditions"]
                if item["kind"] == "state_token"
            },
        )
        chain_steps = hypothesis["possible_chain"]
        self.assertEqual(chain_steps[-1]["step_type"], "hypothesis")
        self.assertEqual(chain_steps[0]["step_type"], "local_bridge")
        self.assertEqual(chain_steps[0]["record_id"], "local:access-1")

    def test_existing_repo_class_suppresses_hypothesis(self) -> None:
        self._write("local_access.yaml", self._LOCAL_ACCESS)
        self._write("local_target.yaml", self._LOCAL_TARGET)
        self._write("remote_analogue.yaml", self._REMOTE_ANALOGUE)
        self._write("local_existing.yaml", self._LOCAL_EXISTING_CLASS)

        payload = self.tool.build_payload(self.tag_dir, limit=10)

        self.assertEqual(payload["total_hypotheses"], 0)
        self.assertGreaterEqual(payload["filtered_existing_class"], 1)
        self.assertFalse(payload["same_class_variant_mode"])

    def test_same_class_variant_mode_emits_distinct_component_hypothesis(self) -> None:
        self._write("local_access.yaml", self._LOCAL_ACCESS)
        self._write("local_target.yaml", self._LOCAL_TARGET)
        self._write("remote_analogue.yaml", self._REMOTE_ANALOGUE)
        self._write("local_existing.yaml", self._LOCAL_EXISTING_CLASS)

        payload = self.tool.build_payload(
            self.tag_dir,
            limit=10,
            same_class_variants=True,
        )

        self.assertTrue(payload["same_class_variant_mode"])
        self.assertEqual(payload["total_hypotheses"], 1)
        self.assertEqual(payload["same_class_variants_emitted"], 1)
        hypothesis = payload["hypotheses"][0]
        self.assertEqual(hypothesis["generation_mode"], "same_class_variant_advisory")
        self.assertEqual(
            hypothesis["novel_attack_class"],
            "privilege-escalation-fund-theft",
        )
        self.assertIn("same_class_variant", hypothesis)
        self.assertIn(
            "distinct_target_component",
            hypothesis["same_class_variant"]["signals"],
        )
        self.assertEqual(
            hypothesis["same_class_variant"]["local_same_class_refs"][0]["record_id"],
            "local:drain-4",
        )
        self.assertIn("already exists", hypothesis["novelty_rationale"])

    def test_target_repo_filter_limits_scope(self) -> None:
        self._write("local_access.yaml", self._LOCAL_ACCESS)
        self._write("local_target.yaml", self._LOCAL_TARGET)
        self._write("remote_analogue.yaml", self._REMOTE_ANALOGUE)

        miss = self.tool.build_payload(self.tag_dir, target_repo="other/repo")
        self.assertEqual(miss["targets_considered"], 0)
        self.assertEqual(miss["total_hypotheses"], 0)

        hit = self.tool.build_payload(self.tag_dir, target_repo="example/vault")
        self.assertEqual(hit["targets_considered"], 2)
        self.assertEqual(hit["total_hypotheses"], 1)

    def test_max_targets_bounds_default_scan(self) -> None:
        self._write("local_access.yaml", self._LOCAL_ACCESS)
        self._write("local_target.yaml", self._LOCAL_TARGET)
        self._write("remote_analogue.yaml", self._REMOTE_ANALOGUE)

        capped = self.tool.build_payload(self.tag_dir, max_targets=1)

        self.assertEqual(capped["total_target_candidates"], 3)
        self.assertEqual(capped["targets_considered"], 1)
        self.assertEqual(capped["target_scan_limit"], 1)
        self.assertTrue(capped["targets_truncated"])
        self.assertEqual(capped["filters"]["max_targets"], 1)

        uncapped = self.tool.build_payload(self.tag_dir, max_targets=None)
        self.assertEqual(uncapped["targets_considered"], 3)
        self.assertIsNone(uncapped["target_scan_limit"])
        self.assertFalse(uncapped["targets_truncated"])

    def test_cli_json_and_jsonl_paths(self) -> None:
        self._write("local_access.yaml", self._LOCAL_ACCESS)
        self._write("local_target.yaml", self._LOCAL_TARGET)
        self._write("remote_analogue.yaml", self._REMOTE_ANALOGUE)

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--tag-dir",
                str(self.tag_dir),
                "--json",
                "--same-class-variants",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["total_hypotheses"], 1)

        out_path = self.tmp_path / "novel_vectors.jsonl"
        proc_out = subprocess.run(
            [sys.executable, str(TOOL), "--tag-dir", str(self.tag_dir), "--out", str(out_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_out.returncode, 0, proc_out.stderr)
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["schema"], "auditooor.hackerman_novel_vector_hypothesis.v1")
        self.assertTrue(rows[0]["advisory_only"])

    def test_cli_empty_state_includes_diagnostics(self) -> None:
        self._write("local_access.yaml", self._LOCAL_ACCESS)
        self._write("local_target.yaml", self._LOCAL_TARGET)
        self._write("remote_analogue.yaml", self._REMOTE_ANALOGUE)
        self._write("local_existing.yaml", self._LOCAL_EXISTING_CLASS)

        proc = subprocess.run(
            [sys.executable, str(TOOL), "--tag-dir", str(self.tag_dir), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["total_hypotheses"], 0)
        self.assertIn("diagnostics", payload)
        self.assertIn("empty_state", payload["diagnostics"])
        self.assertIn(payload["diagnostics"]["empty_state"]["status"], {"empty", "no_targets", "no_analogues"})


if __name__ == "__main__":
    unittest.main()
