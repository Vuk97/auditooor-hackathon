from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-proof-artifact-import-queue.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_proof_artifact_import_queue", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanProofArtifactImportQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.audits_root = self.root / "audits"
        self.repo_root = self.root / "repo"
        self.audits_root.mkdir()
        self.repo_root.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_queue(self, rows: list[dict[str, object]]) -> Path:
        path = self.root / "queue.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        return path

    def _write_audit_file(self, relative: str, text: str = "ok\n") -> Path:
        parts = Path(relative).parts
        self.assertGreaterEqual(len(parts), 2)
        self.assertEqual(parts[0], "audits")
        path = self.audits_root / Path(*parts[1:])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _base_row(self, *, proof_path: str = "audits/dydx/poc-tests/lead/proof_test.go") -> dict[str, object]:
        return {
            "schema": self.tool.QUEUE_SCHEMA,
            "engagement": "dydx",
            "queue_key": "paste_ready/sample.md",
            "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
            "submission_status": "paste_ready",
            "submission_title": "Sample bug",
            "suggested_record_slug": "sample-bug",
            "suggested_source_audit_ref": "paste_ready/sample.md",
            "candidate_count": 1,
            "proof_artifact_candidates": [
                {
                    "candidate_artifact_kind": "test-file",
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": proof_path,
                    "promotion_review_reason": "explicit proof",
                    "raw_candidate_proof_path": proof_path,
                }
            ],
        }

    def test_ready_queue_row_emits_review_packet_without_mutation(self) -> None:
        self._write_audit_file("audits/dydx/submissions/paste_ready/sample.md", "draft")
        self._write_audit_file("audits/dydx/poc-tests/lead/proof_test.go", "package proof\n")
        queue = self._write_queue([self._base_row()])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        self.assertEqual(summary["packets"], 1)
        self.assertEqual(summary["ready_for_manual_record_creation"], 1)
        self.assertEqual(summary["blocked"], 0)
        packets = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(packets[0]["schema"], self.tool.PACKET_SCHEMA)
        self.assertEqual(packets[0]["validation_status"], "ready_for_manual_record_creation")
        self.assertEqual(packets[0]["recommended_next_action"], "manual_create_hackerman_record")
        self.assertEqual(packets[0]["blockers"], [])
        self.assertEqual(packets[0]["artifact_candidates"][0]["exists"], True)

    def test_blocks_path_traversal_missing_artifact_wrong_kind_and_wrong_engagement(self) -> None:
        self._write_audit_file("audits/dydx/submissions/paste_ready/sample.md", "draft")
        row = self._base_row(proof_path="audits/mezo/poc-tests/lead/proof.txt")
        row["proof_artifact_candidates"][0]["candidate_artifact_kind"] = "test-file"  # type: ignore[index]
        queue = self._write_queue([row])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        self.assertEqual(summary["blocked"], 1)
        packet = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        self.assertIn("candidate_artifact_missing", packet["blockers"])
        self.assertIn("engagement_mismatch", packet["blockers"])
        self.assertIn("artifact_kind_mismatch", packet["blockers"])

        traversal = self._base_row(proof_path="../../etc/passwd")
        queue = self._write_queue([traversal])
        summary = self.tool.build_review_packets(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )
        self.assertEqual(summary["blocked"], 1)
        packet = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        self.assertIn("unsafe_candidate_proof_path", packet["blockers"])

    def test_blocks_duplicate_candidate_path_across_queue_rows(self) -> None:
        self._write_audit_file("audits/dydx/submissions/paste_ready/sample.md", "draft")
        self._write_audit_file("audits/dydx/submissions/paste_ready/second.md", "draft")
        self._write_audit_file("audits/dydx/poc-tests/lead/proof_test.go", "package proof\n")
        first = self._base_row()
        second = self._base_row()
        second["queue_key"] = "paste_ready/second.md"
        second["submission_path"] = "audits/dydx/submissions/paste_ready/second.md"
        queue = self._write_queue([first, second])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        self.assertEqual(summary["blocked"], 2)
        self.assertEqual(summary["blocker_counts"]["duplicate_candidate_proof_path"], 2)

    def test_blocks_stale_submission_when_newer_sibling_exists(self) -> None:
        old = self._write_audit_file("audits/dydx/submissions/paste_ready/sample.md", "draft")
        self._write_audit_file("audits/dydx/poc-tests/lead/proof_test.go", "package proof\n")
        time.sleep(0.01)
        new = self._write_audit_file("audits/dydx/submissions/paste_ready/sample_v2.md", "draft v2")
        os.utime(new, None)
        os.utime(old, (old.stat().st_atime - 10, old.stat().st_mtime - 10))
        queue = self._write_queue([self._base_row()])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        self.assertEqual(summary["blocked"], 1)
        packet = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        self.assertIn("stale_submission_newer_sibling", packet["blockers"])

    def test_dry_run_does_not_write_packets(self) -> None:
        self._write_audit_file("audits/dydx/submissions/paste_ready/sample.md", "draft")
        self._write_audit_file("audits/dydx/poc-tests/lead/proof_test.go", "package proof\n")
        queue = self._write_queue([self._base_row()])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
            dry_run=True,
        )

        self.assertEqual(summary["ready_for_manual_record_creation"], 1)
        self.assertFalse(out.exists())

    def test_allows_shell_script_as_runnable_poc_artifact(self) -> None:
        self._write_audit_file("audits/dydx/submissions/paste_ready/sample.md", "draft")
        self._write_audit_file("audits/dydx/poc-tests/lead/demonstrate.sh", "#!/bin/sh\nexit 0\n")
        row = self._base_row(proof_path="audits/dydx/poc-tests/lead/demonstrate.sh")
        row["proof_artifact_candidates"][0]["candidate_artifact_kind"] = "poc-tests"  # type: ignore[index]
        queue = self._write_queue([row])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        self.assertEqual(summary["ready_for_manual_record_creation"], 1)
        packet = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(packet["blockers"], [])

    def test_status_only_reconciliation_candidate_emits_review_packet(self) -> None:
        self._write_audit_file(
            "audits/polymarket/submissions/submitted/R77_archive/R77-08.md",
            "## Submission 13 - VERIFIED PoC\n\n## Finding Title\n\n```\nNegRiskOperator unflag race preempts admin emergency resolution\n```\n",
        )
        self._write_audit_file("audits/polymarket/pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol", "contract Proof {}\n")
        row = {
            "schema": self.tool.RECONCILIATION_SCHEMA,
            "reconciliation_status": "record_creation_candidate",
            "recommended_action": "create_or_link_hackerman_record_before_proof_artifact_path",
            "mutation_allowed": False,
            "engagement": "polymarket",
            "queue_key": "submitted/R77_archive/R77-08.md",
            "submission_ref": "submitted/R77_archive/R77-08.md",
            "submission_path": "audits/polymarket/submissions/submitted/R77_archive/R77-08.md",
            "submission_status": "submitted",
            "submission_title": "Submission 13 - R77-08 - Medium - VERIFIED PoC",
            "candidate_count": 1,
            "proof_artifact_candidates": [
                {
                    "candidate_artifact_kind": "test-file",
                    "candidate_path_occurrence": 3,
                    "candidate_proof_path": "audits/polymarket/pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol",
                    "promotion_review_reason": "blocked: submission_status_not_paste_ready_or_filed",
                    "raw_candidate_proof_path": "audits/polymarket/pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol",
                }
            ],
        }
        queue = self._write_queue([row])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets_from_status_only_reconciliation(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        self.assertEqual(summary["queue_schema"], self.tool.RECONCILIATION_SCHEMA)
        self.assertEqual(summary["packets"], 1)
        self.assertEqual(summary["ready_for_manual_record_creation"], 1)
        packet = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(packet["schema"], self.tool.PACKET_SCHEMA)
        self.assertEqual(packet["suggested_source_audit_ref"], "submitted/R77_archive/R77-08.md")
        self.assertEqual(packet["submission_title"], "NegRiskOperator unflag race preempts admin emergency resolution")
        self.assertEqual(packet["validation_status"], "ready_for_manual_record_creation")
        self.assertEqual(packet["artifact_candidates"][0]["exists"], True)

    def test_status_only_reconciliation_prefers_test_artifact_over_logs_and_source(self) -> None:
        self._write_audit_file(
            "audits/base-azul/submissions/ready/FN2-READY.md",
            "- **Title field:** `TEE/ZK journals omit L2 chain ID, enabling cross-deployment proof replay`\n",
        )
        self._write_audit_file("audits/base-azul/submissions/verification_runs/FN2_REPRODUCE_CLEAN.log", "failed import\n")
        self._write_audit_file("audits/base-azul/external/contracts/src/multiproof/AggregateVerifier.sol", "contract Source {}\n")
        self._write_audit_file("audits/base-azul/differential_fuzz/ws_b_solidity_invariant/test/FN2_PoC.t.sol", "contract Proof {}\n")
        row = {
            "schema": self.tool.RECONCILIATION_SCHEMA,
            "reconciliation_status": "record_creation_candidate",
            "mutation_allowed": False,
            "engagement": "base-azul",
            "queue_key": "ready/FN2-READY.md",
            "submission_ref": "ready/FN2-READY.md",
            "submission_path": "audits/base-azul/submissions/ready/FN2-READY.md",
            "submission_status": "ready",
            "submission_title": "FN2 - Medium - VERIFIED PoC - Immunefi Ready Submission",
            "candidate_count": 3,
            "proof_artifact_candidates": [
                {
                    "candidate_artifact_kind": "execution-output",
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/base-azul/submissions/verification_runs/FN2_REPRODUCE_CLEAN.log",
                    "raw_candidate_proof_path": "audits/base-azul/submissions/verification_runs/FN2_REPRODUCE_CLEAN.log",
                },
                {
                    "candidate_artifact_kind": "test-file",
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/base-azul/external/contracts/src/multiproof/AggregateVerifier.sol",
                    "raw_candidate_proof_path": "audits/base-azul/external/contracts/src/multiproof/AggregateVerifier.sol",
                },
                {
                    "candidate_artifact_kind": "test-file",
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/base-azul/differential_fuzz/ws_b_solidity_invariant/test/FN2_PoC.t.sol",
                    "raw_candidate_proof_path": "audits/base-azul/differential_fuzz/ws_b_solidity_invariant/test/FN2_PoC.t.sol",
                },
            ],
        }
        queue = self._write_queue([row])
        out = self.root / "packets.jsonl"

        self.tool.build_review_packets_from_status_only_reconciliation(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        packet = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(packet["submission_title"], "TEE/ZK journals omit L2 chain ID, enabling cross-deployment proof replay")
        self.assertEqual(
            packet["artifact_candidates"][0]["candidate_proof_path"],
            "audits/base-azul/differential_fuzz/ws_b_solidity_invariant/test/FN2_PoC.t.sol",
        )

    def test_status_only_reconciliation_skips_non_creation_rows(self) -> None:
        row = {
            "schema": self.tool.RECONCILIATION_SCHEMA,
            "reconciliation_status": "status_not_final",
            "engagement": "base-azul",
            "submission_path": "audits/base-azul/submissions/packaged/FN2.md",
            "candidate_count": 0,
            "proof_artifact_candidates": [],
        }
        queue = self._write_queue([row])
        out = self.root / "packets.jsonl"

        summary = self.tool.build_review_packets_from_status_only_reconciliation(
            queue,
            out_path=out,
            audits_root=self.audits_root,
            repo_root=self.repo_root,
        )

        self.assertEqual(summary["packets"], 0)
        self.assertEqual(summary["skipped_counts"], {"status_not_final": 1})
        self.assertEqual(out.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
