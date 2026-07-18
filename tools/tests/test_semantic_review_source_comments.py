import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "semantic_review_source_comments",
    ROOT / "tools" / "semantic-review-source-comments.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class SemanticReviewSourceCommentsTest(unittest.TestCase):
    def _workspace(self) -> tuple[Path, dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        workspace = Path(temporary.name) / "ws"
        source = workspace / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("// Per-IP rate limiting will be wired in front of this handler.\n", encoding="utf-8")
        comment = {
            "comment_id": "comment-1",
            "source_file": str(source),
            "line": 1,
            "text": "Per-IP rate limiting will be wired in front of this handler.",
            "context": "// Per-IP rate limiting will be wired in front of this handler.",
        }
        audit = workspace / ".auditooor"
        audit.mkdir()
        (audit / "source_comment_reconciliation.json").write_text(
            json.dumps({"comments": [comment]}), encoding="utf-8"
        )
        return workspace, comment

    def _decisions(self, comment: dict, snapshot: str, **overrides: object) -> dict:
        row = {
            "comment_id": comment["comment_id"],
            "disposition": "planned-remediation-oos",
            "reviewer_id": "semantic-reviewer-1",
            "reviewed_at": "2026-07-18T12:00:00Z",
            "review_method": "read comment and surrounding source context",
            "rationale": "The team explicitly describes unfinished planned remediation.",
        }
        row.update(overrides)
        return {
            "schema": MODULE.DECISION_SCHEMA,
            "source_snapshot_sha256": snapshot,
            "decisions": [row],
        }

    def test_explicit_reviewer_decision_is_published_without_regex_classification(self):
        workspace, comment = self._workspace()
        snapshot = MODULE._snapshot([comment])
        decisions = self._decisions(comment, snapshot)
        decision_path = workspace / ".auditooor" / "source_comment_review_decisions.json"
        decision_path.write_text(json.dumps(decisions), encoding="utf-8")

        payload = MODULE.run(workspace, decision_path, workspace / ".auditooor" / "source_comment_analysis.json")

        self.assertEqual(MODULE.SCHEMA, payload["schema_version"])
        self.assertEqual("planned-remediation-oos", payload["analyses"][0]["disposition"])
        self.assertEqual("semantic-reviewer-1", payload["analyses"][0]["reviewer_id"])

    def test_missing_or_stale_reviewer_decisions_fail_closed(self):
        workspace, comment = self._workspace()
        decision_path = workspace / ".auditooor" / "source_comment_review_decisions.json"
        with self.assertRaisesRegex(MODULE.ReviewError, "source_comment_review_decisions_missing"):
            MODULE.run(workspace, decision_path, workspace / ".auditooor" / "source_comment_analysis.json")

        decisions = self._decisions(comment, "stale")
        decision_path.write_text(json.dumps(decisions), encoding="utf-8")
        with self.assertRaisesRegex(MODULE.ReviewError, "source_comment_review_snapshot_mismatch"):
            MODULE.run(workspace, decision_path, workspace / ".auditooor" / "source_comment_analysis.json")

    def test_fixed_disposition_requires_current_code_evidence(self):
        workspace, comment = self._workspace()
        decisions = self._decisions(
            comment,
            MODULE._snapshot([comment]),
            disposition="claimed-fixed-verified",
        )
        with self.assertRaisesRegex(MODULE.ReviewError, "source_comment_review_fixed_evidence_missing"):
            MODULE.validate_review_decisions([comment], decisions)


if __name__ == "__main__":
    unittest.main()
