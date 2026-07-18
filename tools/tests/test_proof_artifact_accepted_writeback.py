from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "proof-artifact-accepted-writeback.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("proof_artifact_accepted_writeback", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_module()


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _make_file(root: Path, rel_path: str, body: str = "source\n") -> str:
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return rel_path


def _valid_source(root: Path) -> str:
    return _make_file(root, "projects/dydx/submissions/SUBMISSIONS.md", "accepted source row\n")


def _valid_proof(root: Path, rel_path: str = "audits/dydx/poc-tests/lead_test.go") -> str:
    return _make_file(root, rel_path, "=== RUN   TestLead\n--- PASS: TestLead (0.01s)\n")


class ProofArtifactAcceptedWritebackTest(unittest.TestCase):
    def test_accepted_vs_pending_filtering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accepted_writeback_") as tmp:
            root = Path(tmp)
            source = _valid_source(root)
            proof = _valid_proof(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(
                outcomes,
                [
                    {
                        "outcome_id": "o-accepted",
                        "status": "Accepted",
                        "workspace": "alpha",
                        "title": "accepted finding",
                        "proof_artifact": proof,
                        "source": source,
                        "pass_evidence_lines": ["--- PASS: TestLead"],
                    },
                    {
                        "outcome_id": "o-pending",
                        "status": "Pending",
                        "workspace": "alpha",
                        "title": "pending finding",
                        "proof_artifact": proof,
                        "source": source,
                        "pass_evidence_lines": ["--- PASS: TestLead"],
                    },
                ],
            )

            rows, summary = tool.build_writeback_rows(outcomes, workspace_path=root)

            self.assertEqual(len(rows), 2)
            accepted = [row for row in rows if row["promotion_ready"]]
            rejected = [row for row in rows if not row["promotion_ready"]]
            self.assertEqual(len(accepted), 1)
            self.assertEqual(len(rejected), 1)
            self.assertEqual(accepted[0]["outcome_id"], "o-accepted")
            self.assertEqual(accepted[0]["proof_artifact_path"], proof)
            self.assertEqual(accepted[0]["candidate_proof_path"], proof)
            self.assertEqual(accepted[0]["submission_status"], "accepted_outcome")
            self.assertEqual(accepted[0]["verification_tier"], "tier-1-verified-realtime-api")
            self.assertEqual(rejected[0]["outcome_id"], "o-pending")
            self.assertEqual(rejected[0]["submission_status"], "rejected_outcome")
            self.assertIn("non_positive_status", rejected[0]["promotion_rejection_reasons"])
            self.assertEqual(summary["skipped_counts"]["non_positive_status"], 1)
            self.assertEqual(summary["rows_accepted"], 1)
            self.assertEqual(summary["rows_rejected"], 1)

    def test_dedupe_by_platform_finding_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accepted_writeback_") as tmp:
            root = Path(tmp)
            source = _valid_source(root)
            proof1 = _valid_proof(root, "proofs/first.md")
            proof2 = _valid_proof(root, "proofs/second.md")
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(
                outcomes,
                [
                    {
                        "outcome_id": "o-1",
                        "platform_finding_id": "PF-7",
                        "status": "Paid",
                        "title": "first",
                        "proof_path": proof1,
                        "source": source,
                        "proof_evidence": "go test ./... PASS",
                    },
                    {
                        "outcome_id": "o-2",
                        "platform_finding_id": "PF-7",
                        "status": "Rewarded",
                        "title": "second",
                        "proof_path": proof2,
                        "source": source,
                        "proof_evidence": "go test ./... PASS",
                    },
                ],
            )

            rows, summary = tool.build_writeback_rows(outcomes, workspace_path=root)

            self.assertEqual(len(rows), 2)
            accepted = [row for row in rows if row["promotion_ready"]]
            rejected = [row for row in rows if not row["promotion_ready"]]
            self.assertEqual(len(accepted), 1)
            self.assertEqual(len(rejected), 1)
            self.assertEqual(accepted[0]["platform_finding_id"], "PF-7")
            self.assertEqual(accepted[0]["dedupe_basis"], "platform_finding_id")
            self.assertIn("duplicate", rejected[0]["promotion_rejection_reasons"])
            self.assertEqual(summary["skipped_counts"]["duplicate"], 1)

    def test_missing_proof_is_blocked_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accepted_writeback_") as tmp:
            root = Path(tmp)
            source = _valid_source(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(
                outcomes,
                [
                    {
                        "outcome_id": "o-missing",
                        "status": "Accepted",
                        "workspace": "alpha",
                        "title": "missing proof",
                        "source": source,
                        "pass_evidence_lines": ["--- PASS: TestLead"],
                    },
                ],
            )

            rows, summary = tool.build_writeback_rows(outcomes, workspace_path=root)

            self.assertEqual(len(rows), 1)
            self.assertFalse(rows[0]["promotion_ready"])
            self.assertEqual(rows[0]["submission_status"], "rejected_outcome")
            self.assertIn("missing_proof_artifact_blocked", rows[0]["promotion_rejection_reasons"])
            self.assertEqual(summary["skipped_counts"]["missing_proof_artifact_blocked"], 1)

    def test_include_missing_emits_empty_proof_path_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accepted_writeback_") as tmp:
            root = Path(tmp)
            source = _valid_source(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            output = Path(tmp) / "writeback.jsonl"
            _write_jsonl(
                outcomes,
                [
                    {
                        "outcome_id": "o-missing",
                        "report_id": "R-1",
                        "status": "resolved-positive",
                        "workspace": "alpha",
                        "title": "missing proof",
                        "source": source,
                        "proof_evidence": "go test ./... PASS",
                    },
                ],
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--outcomes",
                    str(outcomes),
                    "--output",
                    str(output),
                    "--include-missing",
                    "--workspace",
                    str(root),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["rows_written"], 1)
            written = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0]["outcome_id"], "o-missing")
            self.assertEqual(written[0]["proof_artifact_path"], "")
            self.assertEqual(written[0]["writeback_tier"], "rejected_outcome")
            self.assertEqual(written[0]["promotion_review_status"], "rejected")
            self.assertIn("missing_proof_artifact_blocked", written[0]["promotion_rejection_reasons"])


class F1IndexWritebackTest(unittest.TestCase):
    """Tests for --target-index (F1) mode: accepted -> tier-1 proof_artifact_index row."""

    def _prepare_valid_workspace(self, root: Path) -> tuple[str, str]:
        source = _valid_source(root)
        proof = _valid_proof(root)
        return source, proof

    def _accepted_row(self, **overrides: object) -> dict[str, object]:
        base: dict[str, object] = {
            "outcome_id": "o-f1",
            "platform_finding_id": "CANTINA-42",
            "status": "Accepted",
            "workspace": "dydx",
            "title": "accepted critical finding",
            "proof_artifact": "audits/dydx/poc-tests/lead_test.go",
            "source": "projects/dydx/submissions/SUBMISSIONS.md",
            "pass_evidence_lines": ["--- PASS: TestLead"],
        }
        base.update(overrides)
        return base

    def test_accepted_writes_tier1_row_to_index(self) -> None:
        """Accepted finding -> tier-1-verified-realtime-api row in proof_artifact_index.jsonl."""
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp)
            self._prepare_valid_workspace(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            index = Path(tmp) / "proof_artifact_index.jsonl"
            _write_jsonl(outcomes, [self._accepted_row()])

            rows, summary = tool.build_index_rows(outcomes, workspace_path=root)

            self.assertEqual(len(rows), 1, summary)
            row = rows[0]
            self.assertEqual(row["schema"], "auditooor.hackerman_proof_artifact_index.v1")
            self.assertEqual(row["verification_tier"], "tier-1-verified-realtime-api")
            self.assertEqual(row["platform_finding_id"], "CANTINA-42")
            self.assertEqual(row["candidate_proof_path"], "audits/dydx/poc-tests/lead_test.go")
            self.assertEqual(row["submission_status"], "filed_accepted")
            self.assertEqual(row["confidence"], "high")
            self.assertEqual(row["confidence_score"], 1.0)
            self.assertTrue(row["promotion_ready"])
            self.assertEqual(row["promotion_review_status"], "ready")

            # Also test the merge
            existing, appended, skipped = tool.merge_into_index(index, rows)
            self.assertEqual(existing, 0)
            self.assertEqual(appended, 1)
            self.assertEqual(skipped, 0)

            written = [json.loads(l) for l in index.read_text().splitlines() if l.strip()]
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0]["verification_tier"], "tier-1-verified-realtime-api")
            self.assertEqual(written[0]["platform_finding_id"], "CANTINA-42")

    def test_pending_rejected_not_written_to_index(self) -> None:
        """Pending / rejected outcomes must NOT produce index rows."""
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(outcomes, [
                {
                    "outcome_id": "o-pending",
                    "status": "Pending",
                    "workspace": "dydx",
                    "title": "pending",
                    "proof_artifact": "audits/dydx/poc.go",
                },
                {
                    "outcome_id": "o-rejected",
                    "status": "Rejected",
                    "workspace": "dydx",
                    "title": "rejected",
                    "proof_artifact": "audits/dydx/poc2.go",
                },
                {
                    "outcome_id": "o-dup-root-rejected",
                    "status": "Duplicate (root rejected)",
                    "workspace": "dydx",
                    "title": "dup",
                    "proof_artifact": "audits/dydx/poc3.go",
                },
            ])

            rows, summary = tool.build_index_rows(outcomes)

            self.assertEqual(rows, [], f"Expected 0 rows but got {len(rows)}: {summary}")
            self.assertEqual(summary["skipped_counts"]["non_positive_status"], 3)

    def test_idempotency_no_duplicate_rows(self) -> None:
        """Running merge_into_index twice must not duplicate rows."""
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp)
            self._prepare_valid_workspace(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            index = Path(tmp) / "proof_artifact_index.jsonl"
            _write_jsonl(outcomes, [self._accepted_row()])

            rows, _ = tool.build_index_rows(outcomes, workspace_path=root)

            # First merge
            _, appended1, skipped1 = tool.merge_into_index(index, rows)
            self.assertEqual(appended1, 1)
            self.assertEqual(skipped1, 0)

            # Second merge (idempotent)
            _, appended2, skipped2 = tool.merge_into_index(index, rows)
            self.assertEqual(appended2, 0)
            self.assertEqual(skipped2, 1)

            written = [json.loads(l) for l in index.read_text().splitlines() if l.strip()]
            self.assertEqual(len(written), 1, "Must not duplicate rows on second run")

    def test_no_proof_artifact_blocked_from_index(self) -> None:
        """Accepted finding with NO proof artifact must be refused from the index (no fabrication)."""
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp)
            source = _valid_source(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(outcomes, [{
                "outcome_id": "o-no-proof",
                "platform_finding_id": "CANTINA-99",
                "status": "Accepted",
                "workspace": "dydx",
                "title": "accepted but no proof path",
                "source": source,
                "pass_evidence_lines": ["--- PASS: TestLead"],
            }])

            rows, summary = tool.build_index_rows(outcomes, workspace_path=root)

            self.assertEqual(rows, [], "Must not emit rows when proof artifact is missing")
            self.assertIn("missing_proof_artifact_blocked", summary["skipped_counts"])

    def test_missing_source_refs_block_index_writeback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp)
            _valid_proof(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            row = self._accepted_row()
            row.pop("source")
            _write_jsonl(outcomes, [row])

            rows, summary = tool.build_index_rows(outcomes, workspace_path=root)

            self.assertEqual(rows, [])
            self.assertIn("missing_source_refs", summary["skipped_counts"])

    def test_stale_workspace_source_refs_block_index_writeback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp) / "current"
            root.mkdir()
            old_root = Path(tmp) / "old"
            stale_source = _make_file(old_root, "submissions/SUBMISSIONS.md", "old source\n")
            _valid_proof(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(
                outcomes,
                [
                    self._accepted_row(
                        source=str(old_root / stale_source),
                        workspace_path=str(old_root),
                    )
                ],
            )

            rows, summary = tool.build_index_rows(outcomes, workspace_path=root)

            self.assertEqual(rows, [])
            self.assertIn("stale_workspace", summary["skipped_counts"])
            self.assertIn("stale_workspace_source_refs", summary["skipped_counts"])

    def test_missing_proof_evidence_blocks_index_writeback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp)
            source = _valid_source(root)
            proof = _make_file(root, "audits/dydx/poc-tests/lead_test.go", "notes without execution output\n")
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(outcomes, [self._accepted_row(
                source=source,
                proof_artifact=proof,
                pass_evidence_lines=[],
            )])

            rows, summary = tool.build_index_rows(outcomes, workspace_path=root)

            self.assertEqual(rows, [])
            self.assertIn("missing_proof_evidence", summary["skipped_counts"])

    def test_blocker_marker_blocks_index_and_stays_visible_in_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp)
            self._prepare_valid_workspace(root)
            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(outcomes, [self._accepted_row(
                promotion_blockers=["operator must confirm root accepted row"],
            )])

            index_rows, index_summary = tool.build_index_rows(outcomes, workspace_path=root)
            sidecar_rows, sidecar_summary = tool.build_writeback_rows(outcomes, workspace_path=root)

            self.assertEqual(index_rows, [])
            self.assertIn("blocker_marker_present", index_summary["skipped_counts"])
            self.assertEqual(len(sidecar_rows), 1)
            self.assertFalse(sidecar_rows[0]["promotion_ready"])
            self.assertEqual(sidecar_rows[0]["writeback_tier"], "rejected_outcome")
            self.assertIn("blocker_marker_present", sidecar_rows[0]["promotion_rejection_reasons"])
            self.assertEqual(sidecar_summary["rows_rejected"], 1)

    def test_cli_target_index_flag(self) -> None:
        """--target-index CLI flag routes to F1 writeback mode and merges into index."""
        with tempfile.TemporaryDirectory(prefix="f1_cli_") as tmp:
            root = Path(tmp)
            _valid_source(root)
            _valid_proof(root, "audits/dydx/poc/test.go")
            outcomes = Path(tmp) / "outcomes.jsonl"
            index = Path(tmp) / "proof_artifact_index.jsonl"
            _write_jsonl(outcomes, [self._accepted_row(
                platform_finding_id="CANTINA-77",
                proof_artifact="audits/dydx/poc/test.go",
            )])

            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--outcomes", str(outcomes),
                    "--target-index", str(index),
                    "--workspace", str(root),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["mode"], "f1-index-writeback")
            self.assertEqual(payload["rows_written"], 1)
            self.assertEqual(payload["rows_appended"], 1)
            self.assertEqual(payload["rows_skipped_dupe"], 0)

            written = [json.loads(l) for l in index.read_text().splitlines() if l.strip()]
            self.assertEqual(len(written), 1)
            self.assertEqual(written[0]["platform_finding_id"], "CANTINA-77")
            self.assertEqual(written[0]["verification_tier"], "tier-1-verified-realtime-api")
            self.assertEqual(written[0]["schema"], "auditooor.hackerman_proof_artifact_index.v1")

    def test_merge_preserves_existing_rows(self) -> None:
        """Merging into a non-empty index must preserve pre-existing rows."""
        with tempfile.TemporaryDirectory(prefix="f1_writeback_") as tmp:
            root = Path(tmp)
            self._prepare_valid_workspace(root)
            index = Path(tmp) / "proof_artifact_index.jsonl"
            # Pre-populate with a non-accepted row (different schema, different key)
            existing = {"schema": "auditooor.hackerman_proof_artifact_index.v1",
                        "engagement": "base-azul",
                        "platform_finding_id": "",
                        "candidate_proof_path": "audits/base-azul/poc.sol",
                        "submission_title": "old finding",
                        "submission_status": "paste_ready"}
            index.write_text(json.dumps(existing) + "\n", encoding="utf-8")

            outcomes = Path(tmp) / "outcomes.jsonl"
            _write_jsonl(outcomes, [self._accepted_row()])
            rows, _ = tool.build_index_rows(outcomes, workspace_path=root)

            existing_count, appended, _ = tool.merge_into_index(index, rows)
            self.assertEqual(existing_count, 1)
            self.assertEqual(appended, 1)

            written = [json.loads(l) for l in index.read_text().splitlines() if l.strip()]
            self.assertEqual(len(written), 2, "Must preserve original row + append new one")


if __name__ == "__main__":
    unittest.main()
