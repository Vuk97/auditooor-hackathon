"""Tests for tools/proof-artifact-promotion.py (plan item J3a).

Covers:
  1. Empty sidecar -> missing_artifact, no crash
  2. Ready/blocked split counts are correct
  3. PROMOTE writes correct rows to output sidecar
  4. PROMOTE is idempotent (second run adds 0 rows)
  5. UNBLOCK-AUDIT names the first missing field correctly
  6. Density below 10% -> threshold_met=False
  7. Density at/above 10% -> threshold_met=True
  8. Outcome-link check: linked vs missing vs OUTCOME_LINK_PENDING_REASON
  9. Strict mode exits non-zero when filed rows lack outcome links
 10. JSON output contains required schema fields
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
import tempfile
import os


# ---------------------------------------------------------------------------
# Patch module-level paths before each test via a helper
# ---------------------------------------------------------------------------

def _make_index_row(
    promotion_ready: bool,
    submission_status: str = "paste_ready",
    confidence: str = "high",
    blockers: list[str] | None = None,
    candidate_proof_path: str = "audits/x/PoC.t.sol",
    candidate_artifact_exists: bool = True,
    engagement: str = "test-eng",
    submission_title: str = "Test Finding",
    submission_path: str = "audits/x/submissions/paste_ready/finding.md",
    source_refs: list[str] | None = None,
) -> dict:
    blockers = blockers or []
    if source_refs is None:
        source_refs = [f"audits/{engagement}/contracts/Vault.sol:120"]
    return {
        "schema": "auditooor.hackerman_proof_artifact_index.v1",
        "promotion_ready": promotion_ready,
        "promotion_review_status": "ready" if promotion_ready else "blocked",
        "promotion_review_reason": "explicit high-confidence" if promotion_ready else "blocked: " + (blockers[0] if blockers else ""),
        "promotion_blockers": blockers,
        "promotion_gate_version": "proof-artifact-index-promotion-v1",
        "candidate_proof_path": candidate_proof_path,
        "candidate_artifact_exists": candidate_artifact_exists,
        "candidate_artifact_kind": "test-file",
        "candidate_path_occurrence": 1,
        "candidate_path_specificity": 1.0,
        "confidence": confidence,
        "confidence_score": 1.0 if confidence == "high" else 0.5,
        "engagement": engagement,
        "generated_at": "2026-05-19T10:20:47Z",
        "match_method": "submission-explicit-path",
        "raw_reference": candidate_proof_path,
        "source_refs": source_refs,
        "source_reasons": ["submission_explicit_reference", "referenced_artifact_exists"],
        "submission_path": submission_path,
        "submission_status": submission_status,
        "submission_title": submission_title,
        "token_overlap": [],
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


class TestProofArtifactPromotion(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmp.name)

        # Paths used by tests
        self.index_path = self.tmpdir / "proof_artifact_index.jsonl"
        self.output_path = self.tmpdir / "proof_artifact_promotion_output.jsonl"
        self.outcomes_path = self.tmpdir / "outcomes.jsonl"

        # Pre-create empty files
        self.outcomes_path.parent.mkdir(parents=True, exist_ok=True)
        self.outcomes_path.write_text("", encoding="utf-8")

        # Import module (patch paths after import)
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "proof_artifact_promotion",
            Path(__file__).parent.parent / "proof-artifact-promotion.py",
        )
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_main(self, extra_args: list[str] | None = None) -> int:
        args = [
            "--proof-index", str(self.index_path),
            "--promotion-output", str(self.output_path),
            "--outcomes", str(self.outcomes_path),
        ] + (extra_args or [])
        try:
            return self.mod.main(args)
        except SystemExit as exc:
            return int(exc.code) if exc.code is not None else 0

    # -----------------------------------------------------------------------
    # Test 1: Empty sidecar - no crash, missing_artifact emitted
    # -----------------------------------------------------------------------
    def test_01_empty_sidecar_no_crash(self) -> None:
        """Empty sidecar must NOT crash; must emit missing_artifact."""
        # index_path does not exist
        rc = self._run_main(["--json"])
        self.assertEqual(rc, 0, "should exit 0 on missing sidecar")

    def test_01b_empty_sidecar_json_error(self) -> None:
        """JSON output on missing sidecar must contain error=missing_artifact."""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--json"])
        out = buf.getvalue().strip()
        if out:
            data = json.loads(out)
            self.assertIn("error", data)
            self.assertEqual(data["error"], "missing_artifact")

    # -----------------------------------------------------------------------
    # Test 2: Ready/blocked split counts
    # -----------------------------------------------------------------------
    def test_02_ready_blocked_split(self) -> None:
        """Report must count 2 ready and 3 blocked rows correctly."""
        rows = [
            _make_index_row(True),
            _make_index_row(True),
            _make_index_row(False, blockers=["confidence_not_high"], confidence="medium"),
            _make_index_row(False, blockers=["candidate_artifact_missing"], candidate_artifact_exists=False),
            _make_index_row(False, blockers=["submission_status_not_paste_ready_or_filed"], submission_status="root"),
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["summary"]["promotion_ready"], 2)
        self.assertEqual(data["summary"]["blocked"], 3)
        self.assertEqual(data["summary"]["total_candidates"], 5)

    # -----------------------------------------------------------------------
    # Test 3: PROMOTE writes correct rows
    # -----------------------------------------------------------------------
    def test_03_promote_writes_correct_rows(self) -> None:
        """Promote mode must write exactly the ready rows to output sidecar."""
        rows = [
            _make_index_row(True, candidate_proof_path="audits/x/A.sol", submission_title="Finding A"),
            _make_index_row(True, candidate_proof_path="audits/x/B.sol", submission_title="Finding B"),
            _make_index_row(False, blockers=["confidence_not_high"], confidence="medium"),
        ]
        _write_jsonl(self.index_path, rows)
        rc = self._run_main(["--promote"])
        self.assertEqual(rc, 0)

        promoted = _read_jsonl(self.output_path)
        self.assertEqual(len(promoted), 2, "should promote exactly 2 ready rows")
        titles = {r["submission_title"] for r in promoted}
        self.assertIn("Finding A", titles)
        self.assertIn("Finding B", titles)
        schemas = {r["schema"] for r in promoted}
        self.assertTrue(all("promotion_output" in s for s in schemas))
        # proof_status must be set
        for r in promoted:
            self.assertEqual(r.get("proof_status"), "promotion_ready")

    # -----------------------------------------------------------------------
    # Test 4: PROMOTE is idempotent
    # -----------------------------------------------------------------------
    def test_04_promote_idempotent(self) -> None:
        """Running promote twice must not add duplicate rows."""
        rows = [
            _make_index_row(True, candidate_proof_path="audits/x/A.sol"),
        ]
        _write_jsonl(self.index_path, rows)

        self._run_main(["--promote"])
        first_count = len(_read_jsonl(self.output_path))

        self._run_main(["--promote"])
        second_count = len(_read_jsonl(self.output_path))

        self.assertEqual(first_count, second_count, "second promote must add 0 rows")
        self.assertEqual(first_count, 1)

    # -----------------------------------------------------------------------
    # Test 5: UNBLOCK-AUDIT names the first missing field
    # -----------------------------------------------------------------------
    def test_05_unblock_audit_names_missing_field(self) -> None:
        """Unblock-audit must name the first missing field for each blocked row."""
        rows = [
            _make_index_row(
                False,
                blockers=["submission_status_not_paste_ready_or_filed"],
                submission_status="root",
            ),
            _make_index_row(
                False,
                blockers=["candidate_artifact_missing"],
                candidate_artifact_exists=False,
            ),
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--unblock-audit", "--json"])
        data = json.loads(buf.getvalue())

        ua = data.get("unblock_audit", {})
        self.assertEqual(ua.get("total_blocked"), 2)
        work_rows = ua.get("work_rows", [])
        self.assertEqual(len(work_rows), 2)

        fields = {wr.get("first_missing_field") for wr in work_rows}
        # both fields must be non-empty and descriptive
        for field in fields:
            self.assertTrue(field, "first_missing_field must be non-empty")
            self.assertNotEqual(field, "no blockers listed (unexpected)")

    def test_05b_unblock_audit_specific_blocker(self) -> None:
        """submission_status blocker must mention submission_status in missing field."""
        rows = [
            _make_index_row(
                False,
                blockers=["submission_status_not_paste_ready_or_filed"],
                submission_status="staging",
            ),
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--unblock-audit", "--json"])
        data = json.loads(buf.getvalue())
        work_rows = data["unblock_audit"]["work_rows"]
        self.assertEqual(len(work_rows), 1)
        missing = work_rows[0]["first_missing_field"]
        self.assertIn("submission_status", missing.lower())

    # -----------------------------------------------------------------------
    # Test 6: Density below 10% -> threshold_met=False
    # -----------------------------------------------------------------------
    def test_06_density_below_threshold(self) -> None:
        """3 filed rows, 0 with proof -> density 0% < 10% -> threshold_met=False."""
        rows = [
            _make_index_row(
                False,
                blockers=["confidence_not_high"],
                confidence="medium",
                candidate_proof_path="",
                candidate_artifact_exists=False,
            ),
            _make_index_row(
                False,
                blockers=["confidence_not_high"],
                confidence="medium",
                candidate_proof_path="",
                candidate_artifact_exists=False,
            ),
            _make_index_row(
                False,
                blockers=["confidence_not_high"],
                confidence="medium",
                candidate_proof_path="",
                candidate_artifact_exists=False,
            ),
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--json"])
        data = json.loads(buf.getvalue())
        density = data["density"]
        self.assertFalse(density["threshold_met"])
        self.assertLess(density["density_pct"], 10.0)

    # -----------------------------------------------------------------------
    # Test 7: Density at/above 10% -> threshold_met=True
    # -----------------------------------------------------------------------
    def test_07_density_above_threshold(self) -> None:
        """1 filed with proof, 4 filed without -> density 20% >= 10% -> threshold_met=True."""
        with_proof = _make_index_row(
            True,
            candidate_proof_path="audits/x/PoC.t.sol",
            candidate_artifact_exists=True,
        )
        without_proof_rows = [
            _make_index_row(
                False,
                blockers=["confidence_not_high"],
                confidence="medium",
                candidate_proof_path="",
                candidate_artifact_exists=False,
            )
            for _ in range(4)
        ]
        _write_jsonl(self.index_path, [with_proof] + without_proof_rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--json"])
        data = json.loads(buf.getvalue())
        density = data["density"]
        self.assertTrue(density["threshold_met"])
        self.assertGreaterEqual(density["density_pct"], 10.0)

    # -----------------------------------------------------------------------
    # Test 8: Outcome-link check
    # -----------------------------------------------------------------------
    def test_08_outcome_link_check(self) -> None:
        """Filed rows: one with matching outcome title, one with pending reason, one missing."""
        title_linked = "Reentrancy in Vault.withdraw leads to fund drain"
        title_missing = "Unrelated unlinked finding that has no outcome"

        index_rows = [
            _make_index_row(True, submission_title=title_linked),
            _make_index_row(True, submission_title=title_missing),
        ]
        # Add OUTCOME_LINK_PENDING_REASON to the second
        index_rows.append(
            dict(
                _make_index_row(True, submission_title="Finding with pending reason"),
                OUTCOME_LINK_PENDING_REASON="Submitted 2026-05-20, awaiting platform response",
            )
        )
        _write_jsonl(self.index_path, index_rows)

        # Write matching outcome
        outcome = {
            "finding_id": "999",
            "title": title_linked,
            "status": "In Review",
            "outcome": "pending",
            "workspace": "test-eng",
            "workspace_path": "test",
            "lane": "test",
            "date": "2026-05-01",
            "severity": "High",
            "source": "test",
            "fp_reason": None,
        }
        with self.outcomes_path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(outcome) + "\n")

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--json"])
        data = json.loads(buf.getvalue())
        ol = data["outcome_links"]

        self.assertEqual(ol["pending_reason"], 1)
        self.assertGreaterEqual(ol["filed_rows"], 3)

    # -----------------------------------------------------------------------
    # Test 9: Strict mode exits non-zero when missing outcome links
    # -----------------------------------------------------------------------
    def test_09_strict_mode_exit_nonzero(self) -> None:
        """Strict mode must return non-zero exit code when filed rows lack outcome links."""
        rows = [
            _make_index_row(True, submission_title="Orphan finding with no outcome"),
        ]
        _write_jsonl(self.index_path, rows)
        # No outcomes written
        rc = self._run_main(["--strict", "--json"])
        # strict_fail should cause non-zero
        self.assertNotEqual(rc, 0, "strict mode must exit non-zero when missing links")

    def test_09b_strict_mode_passes_when_all_linked(self) -> None:
        """Strict mode must return 0 when all filed rows are linked."""
        title = "Reentrancy in Vault.withdraw leads to fund drain"
        rows = [_make_index_row(True, submission_title=title)]
        _write_jsonl(self.index_path, rows)
        # Write matching outcome
        outcome = {
            "finding_id": "1",
            "title": title,
            "status": "In Review",
            "outcome": "pending",
            "workspace": "test-eng",
            "workspace_path": "test",
            "lane": "test",
            "date": "2026-05-01",
            "severity": "High",
            "source": "test",
            "fp_reason": None,
        }
        with self.outcomes_path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(outcome) + "\n")

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self._run_main(["--strict", "--json"])
        self.assertEqual(rc, 0)

    # -----------------------------------------------------------------------
    # Test 10: JSON schema fields
    # -----------------------------------------------------------------------
    def test_10_json_schema_fields(self) -> None:
        """JSON output must contain required top-level schema fields."""
        rows = [_make_index_row(True)]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self._run_main(["--json"])
        data = json.loads(buf.getvalue())

        required_fields = ["schema", "generated_at", "summary", "density", "outcome_links", "blocked_by_reason"]
        for field in required_fields:
            self.assertIn(field, data, f"missing required field: {field}")

        self.assertEqual(data["schema"], "auditooor.proof_artifact_promotion.v1")
        summary_fields = ["total_candidates", "promotion_ready", "blocked"]
        for field in summary_fields:
            self.assertIn(field, data["summary"], f"missing summary field: {field}")

        density_fields = ["filed_rows", "rows_with_proof", "density_pct", "threshold_pct", "threshold_met"]
        for field in density_fields:
            self.assertIn(field, data["density"], f"missing density field: {field}")

        ol_fields = ["filed_rows", "linked", "pending_reason", "missing_link"]
        for field in ol_fields:
            self.assertIn(field, data["outcome_links"], f"missing outcome_links field: {field}")

    # -----------------------------------------------------------------------
    # Strict promotion gate focused cases
    # -----------------------------------------------------------------------
    def test_11_strict_promotable_row_writes(self) -> None:
        """A ready row with current source refs and proof evidence promotes."""
        source_ref = "audits/test-eng/contracts/Vault.sol:120"
        rows = [
            _make_index_row(
                True,
                candidate_proof_path="audits/test-eng/poc-tests/Finding.t.sol",
                source_refs=[source_ref],
            )
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self._run_main(["--promote", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["promote_result"]["promoted_new"], 1)
        self.assertEqual(data["promote_result"]["rejected"], 0)

        promoted = _read_jsonl(self.output_path)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["valid_current_workspace_source_refs"], [source_ref])
        self.assertTrue(promoted[0]["strict_promotion_checks"]["current_workspace_source_refs"])

    def test_12_strict_missing_source_refs_rejects(self) -> None:
        """A ready row without source refs stays visible as rejected."""
        rows = [
            _make_index_row(
                True,
                candidate_proof_path="audits/test-eng/poc-tests/Finding.t.sol",
                source_refs=[],
            )
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self._run_main(["--promote", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        promote = data["promote_result"]
        self.assertEqual(promote["promoted_new"], 0)
        self.assertEqual(promote["rejected"], 1)
        self.assertIn("missing_current_workspace_source_refs", promote["rejection_counts"])
        self.assertIn(
            "missing_current_workspace_source_refs",
            promote["rejected_rows"][0]["promotion_rejection_reasons"],
        )
        self.assertEqual(_read_jsonl(self.output_path), [])

    def test_13_strict_stale_workspace_source_refs_rejects(self) -> None:
        """Source refs pointing at a sibling workspace are typed stale."""
        rows = [
            _make_index_row(
                True,
                candidate_proof_path="audits/test-eng/poc-tests/Finding.t.sol",
                source_refs=["audits/other-eng/contracts/Vault.sol:120"],
            )
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self._run_main(["--promote", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        reasons = data["promote_result"]["rejected_rows"][0]["promotion_rejection_reasons"]
        self.assertIn("stale_workspace_source_refs", reasons)
        self.assertEqual(data["promote_result"]["promoted_new"], 0)

    def test_14_strict_advisory_only_rejects(self) -> None:
        """Advisory-only rows cannot promote even with proof-shaped paths."""
        row = _make_index_row(
            True,
            candidate_proof_path="audits/test-eng/poc-tests/Finding.t.sol",
        )
        row["advisory_only"] = True
        _write_jsonl(self.index_path, [row])

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self._run_main(["--promote", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        reasons = data["promote_result"]["rejected_rows"][0]["promotion_rejection_reasons"]
        self.assertIn("advisory_only_marker", reasons)
        self.assertEqual(data["promote_result"]["promoted_new"], 0)

    def test_15_strict_blocker_propagation_rejects(self) -> None:
        """Existing blocker strings propagate into promotion rejection reasons."""
        rows = [
            _make_index_row(
                True,
                blockers=["confidence_not_high"],
                candidate_proof_path="audits/test-eng/poc-tests/Finding.t.sol",
            )
        ]
        _write_jsonl(self.index_path, rows)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self._run_main(["--promote", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        reasons = data["promote_result"]["rejected_rows"][0]["promotion_rejection_reasons"]
        self.assertIn("promotion_blocker:confidence_not_high", reasons)
        self.assertIn("promotion_blocker:confidence_not_high", data["promote_result"]["rejection_counts"])
        self.assertEqual(data["promote_result"]["promoted_new"], 0)


if __name__ == "__main__":
    unittest.main()
