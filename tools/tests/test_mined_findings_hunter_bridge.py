from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "mined-findings-hunter-bridge.py"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class MinedFindingsHunterBridgeTests(unittest.TestCase):
    """Contract tests for the local mined-findings -> hunter-obligations bridge."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="mined-findings-hunter-bridge-")
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run_bridge(self, *extra_args: str) -> dict:
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(self.ws),
                "--generated-at",
                "2026-05-21T00:00:00Z",
                "--print-json",
                *extra_args,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    def write_mining_dashboard(self) -> None:
        _write_json(
            self.ws / ".auditooor" / "mining_coverage_dashboard.json",
            {
                "schema": "auditooor.mining_coverage_dashboard.v1",
                "generated_at": "2026-05-21T00:00:00Z",
                "rows": [
                    {
                        "source_id": "bridge_incident_delta",
                        "name": "Bridge incident delta",
                        "status": "backlog",
                        "network_required": True,
                        "output_path": str(self.ws.resolve() / ".auditooor" / "mined" / "bridge_incident"),
                        "source_obligations": [
                            {
                                "obligation_id": "decode-selector",
                                "status": "open",
                                "obligation_type": "transaction_decode_validation",
                                "required_evidence": (
                                    "Decode selector 0x12345678 against the source-only smart contract "
                                    "repository and map it to the settlement path."
                                ),
                                "source_refs": [
                                    "https://example.invalid/tx/0xabc",
                                    ".auditooor/mined/bridge_incident/record.yaml",
                                    "/tmp/provider-output/raw-claim.json",
                                ],
                            },
                            {
                                "obligation_id": "root-cause",
                                "status": "open",
                                "obligation_type": "root_cause_validation",
                                "required_evidence": (
                                    "Prove whether message binding or nonce consumption is missing in the "
                                    "source-only smart contract repository."
                                ),
                                "source_refs": [".auditooor/mined/bridge_incident/record.yaml"],
                            },
                            {
                                "obligation_id": "primary-source",
                                "status": "closed",
                                "obligation_type": "primary_source_reconciliation",
                                "required_evidence": "Find a first-party incident response.",
                                "source_refs": ["https://example.invalid/postmortem"],
                            },
                        ],
                    }
                ],
            },
        )

    def write_target_scope_hints(self) -> None:
        (self.ws / "SCOPE.md").write_text(
            (
                "Scope: source-only Solidity bridge smart contract repository. "
                "Review bridge notary verifier and hardcoded chain identity bypasses verifier.\n"
            ),
            encoding="utf-8",
        )
        source = self.ws / "contracts" / "BridgeNotary.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "contract BridgeNotary { function verify(bytes32 messageRoot) external {} }\n",
            encoding="utf-8",
        )

    def test_cli_writes_bridge_summary_and_ranked_hacker_question_obligations(self) -> None:
        self.write_mining_dashboard()

        summary = self._run_bridge()

        bridge_path = self.ws / ".auditooor" / "mined_findings_hunter_bridge.json"
        obligations_path = self.ws / ".auditooor" / "mined_findings_hunter_obligations.jsonl"
        self.assertTrue(bridge_path.is_file())
        self.assertTrue(obligations_path.is_file())
        self.assertEqual(summary["schema"], "auditooor.mined_findings_hunter_bridge.v1")
        self.assertEqual(summary["generated_at_utc"], "2026-05-21T00:00:00Z")
        self.assertEqual(summary["workspace"], "<workspace>")
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["summary"]["workspace_lessons"], 2)
        self.assertEqual(summary["summary"]["corpus_lessons"], 0)
        self.assertEqual(summary["summary"]["obligations_emitted"], 2)
        self.assertEqual(
            summary["summary"]["by_source_kind"],
            {"mining_coverage_source_obligation": 2},
        )
        self.assertTrue(summary["advisory_only"])
        self.assertTrue(summary["fail_closed"])
        self.assertEqual(summary["network_access"], "not_required")
        self.assertFalse(summary["target_profile"]["has_target_signals"])
        self.assertEqual(summary["corpus_inputs"]["skipped_reason"], "no_target_profile_signals")

        rows = _read_jsonl(obligations_path)
        self.assertEqual(len(rows), 2)
        self.assertEqual([row["rank"] for row in rows], [1, 2])
        self.assertEqual(
            {row["source_obligation_id"] for row in rows},
            {"decode-selector", "root-cause"},
        )
        self.assertTrue(all(row["source_kind"] == "mining_coverage_source_obligation" for row in rows))

        for row in rows:
            self.assertEqual(row["schema"], "auditooor.hacker_question_obligation.v1")
            self.assertRegex(row["obligation_id"], r"^[0-9a-f]{12}$")
            self.assertEqual(row["state"], "open")
            self.assertEqual(row["question_source"], "mined-finding")
            self.assertEqual(row["proof_gate"], "scope_appropriate_mined_lesson_verification")
            self.assertEqual(row["scope_evidence_mode"], "source_only")
            self.assertTrue(row["source_proof_required"])
            self.assertFalse(row["live_proof_required"])
            self.assertFalse(row["deployment_state_proof_required"])
            self.assertIn("scope", row["scope_evidence_policy"])
            self.assertTrue(row["advisory_only"])
            self.assertTrue(row["fail_closed"])
            self.assertFalse(row["promotion_allowed"])
            self.assertIn("not exploitability", row["claim_boundary"])
            self.assertTrue(row["proof_obligation"])
            self.assertTrue(row["kill_condition"])
            self.assertIsInstance(row["source_refs"], list)

    def test_obligation_ids_are_stable_and_re_run_is_idempotent(self) -> None:
        self.write_mining_dashboard()

        self._run_bridge()
        first_rows = _read_jsonl(self.ws / ".auditooor" / "mined_findings_hunter_obligations.jsonl")
        first_ids = [row["obligation_id"] for row in first_rows]

        self._run_bridge()
        second_rows = _read_jsonl(self.ws / ".auditooor" / "mined_findings_hunter_obligations.jsonl")
        second_ids = [row["obligation_id"] for row in second_rows]

        self.assertEqual(first_ids, second_ids)
        self.assertEqual(len(second_ids), len(set(second_ids)))
        self.assertEqual([row["rank"] for row in second_rows], [1, 2])

    def test_outputs_are_local_only_and_do_not_leak_absolute_workspace_paths(self) -> None:
        self.write_mining_dashboard()

        self._run_bridge()
        bridge_text = (self.ws / ".auditooor" / "mined_findings_hunter_bridge.json").read_text(encoding="utf-8")
        obligations_text = (
            self.ws / ".auditooor" / "mined_findings_hunter_obligations.jsonl"
        ).read_text(encoding="utf-8")
        canonical_text = (
            self.ws / ".auditooor" / "hacker_question_obligations.jsonl"
        ).read_text(encoding="utf-8")
        combined = bridge_text + obligations_text + canonical_text

        self.assertNotIn(str(self.ws), combined)
        self.assertNotIn(str(self.ws.resolve()), combined)
        self.assertNotIn("/tmp/provider-output", combined)
        self.assertIn("<local-path>/raw-claim.json", combined)
        bridge = json.loads(bridge_text)
        self.assertEqual(bridge["network_access"], "not_required")
        self.assertTrue(all(ref.startswith("<workspace>/") for ref in bridge["local_source_refs"]))
        rows = _read_jsonl(self.ws / ".auditooor" / "mined_findings_hunter_obligations.jsonl")
        canonical_rows = _read_jsonl(self.ws / ".auditooor" / "hacker_question_obligations.jsonl")
        self.assertEqual(len(canonical_rows), len(rows))
        self.assertIn("https://example.invalid", json.dumps([row["source_refs"] for row in rows]))
        for row in rows:
            self.assertEqual(row["workspace"], "<workspace>")
            self.assertEqual(row["network_access"], "not_required")
            self.assertEqual(row["scope_evidence_mode"], "source_only")
            self.assertIn("reference only", row["source_ref_boundary"])
        for row in canonical_rows:
            self.assertEqual(row["workspace"], "<workspace>")

    def test_missing_local_mined_artifacts_writes_fail_closed_empty_outputs(self) -> None:
        summary = self._run_bridge()

        obligations_path = self.ws / ".auditooor" / "mined_findings_hunter_obligations.jsonl"
        bridge_path = self.ws / ".auditooor" / "mined_findings_hunter_bridge.json"
        self.assertTrue(bridge_path.is_file())
        self.assertTrue(obligations_path.is_file())
        self.assertEqual(_read_jsonl(obligations_path), [])
        self.assertEqual(summary["summary"]["obligations_emitted"], 0)
        self.assertTrue(summary["fail_closed"])
        self.assertEqual(summary["status"], "no_mined_finding_questions_fail_closed")
        self.assertEqual(summary["target_profile"]["has_target_signals"], False)
        self.assertEqual(summary["corpus_inputs"]["records_considered"], 0)
        self.assertEqual(summary["corpus_inputs"]["skipped_reason"], "no_target_profile_signals")
        self.assertIn("no mined finding questions", summary["blocked_reasons"][0])

    def test_scope_and_source_hints_may_emit_bounded_corpus_mined_finding_obligations(self) -> None:
        self.write_target_scope_hints()

        summary = self._run_bridge("--limit", "3")

        obligations_path = self.ws / ".auditooor" / "mined_findings_hunter_obligations.jsonl"
        rows = _read_jsonl(obligations_path)
        self.assertEqual(summary["status"], "ok")
        self.assertTrue(summary["target_profile"]["has_target_signals"])
        self.assertIn("solidity", summary["target_profile"]["language_hints"])
        self.assertIn("bridge", summary["target_profile"]["domain_hints"])
        self.assertGreater(summary["summary"]["corpus_lessons"], 0)
        self.assertEqual(summary["summary"]["lessons_returned"], 3)
        self.assertEqual(summary["summary"]["obligations_emitted"], 3)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["source_kind"] == "corpus_mined_finding" for row in rows))
        self.assertTrue(all(row["rank"] in {1, 2, 3} for row in rows))
        self.assertTrue(all("scope_evidence_mode" in row for row in rows))
        self.assertTrue(all(row["promotion_allowed"] is False for row in rows))
        self.assertTrue(all(row["network_access"] == "not_required" for row in rows))

    def test_oos_text_alone_does_not_enable_positive_corpus_matching(self) -> None:
        (self.ws / "OOS_PASTED.md").write_text(
            "Out of scope: bridge oracle governance vault staking runtime pallets.\n",
            encoding="utf-8",
        )

        summary = self._run_bridge("--limit", "3")

        self.assertFalse(summary["target_profile"]["has_target_signals"])
        self.assertEqual(summary["target_profile"]["oos_signal_paths"], ["OOS_PASTED.md"])
        self.assertEqual(summary["corpus_inputs"]["records_considered"], 0)
        self.assertEqual(summary["corpus_inputs"]["skipped_reason"], "no_target_profile_signals")
        self.assertEqual(summary["summary"]["corpus_lessons"], 0)

    def test_max_corpus_records_zero_does_not_scan_any_corpus_record(self) -> None:
        self.write_target_scope_hints()

        summary = self._run_bridge("--limit", "3", "--max-corpus-records", "0")

        self.assertTrue(summary["target_profile"]["has_target_signals"])
        self.assertEqual(summary["corpus_inputs"]["records_considered"], 0)
        self.assertEqual(summary["corpus_inputs"]["skipped_reason"], "max_records_zero")
        self.assertEqual(summary["summary"]["corpus_lessons"], 0)

    def test_redaction_does_not_treat_sibling_prefix_paths_as_workspace_paths(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("mined_findings_hunter_bridge", TOOL)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        workspace = Path("/Users/wolf/audit")
        sibling = "/Users/wolf/auditooor-mcp/outside.json"

        self.assertEqual(module._redact_path(sibling, workspace), "<local-path>/outside.json")
        self.assertEqual(
            module._redact_text(f"see {sibling}", workspace),
            "see <local-path>/outside.json",
        )


if __name__ == "__main__":
    unittest.main()
