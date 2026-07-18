from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-proof-artifact-index.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_proof_artifact_index", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanProofArtifactIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.eng = self.root / "dydx"
        (self.eng / "submissions" / "paste_ready").mkdir(parents=True)
        (self.eng / "poc-tests" / "lead_codec").mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
        return path

    def _run(self) -> tuple[dict, list[dict]]:
        out = self.root / "derived" / "proof_artifact_index.jsonl"
        report = self.root / "reports" / "proof_artifact_index_phase_a_2026-05-17.md"
        summary = self.tool.build_index([self.root], out_path=out, report_path=report)
        rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
        return summary, rows

    def _write_current_source_ref(self) -> str:
        self._write(
            self.eng / "src" / "codec.go",
            """
            package src

            func Codec() {}
            """,
        )
        return "workspace:src/codec.go:1"

    def _write_go_proof(self, name: str = "codec_subcall_poc_test.go") -> Path:
        return self._write(
            self.eng / "poc-tests" / "lead_codec" / name,
            """
            package lead_codec

            import "testing"

            func TestCodecSubcallPoC(t *testing.T) {
                t.Log("proof")
            }
            """,
        )

    def test_explicit_submission_reference_emits_high_confidence_row(self) -> None:
        source_ref = self._write_current_source_ref()
        self._write_go_proof()
        self._write(
            self.eng / "submissions" / "paste_ready" / "codec-subcall-HIGH.md",
            f"""
            # Codec subcall cap weakening

            source_refs: {source_ref}
            proof_artifact: poc-tests/lead_codec/codec_subcall_poc_test.go
            """,
        )

        summary, rows = self._run()

        self.assertEqual(summary["candidate_rows"], 1)
        self.assertEqual(rows[0]["candidate_proof_path"], "audits/dydx/poc-tests/lead_codec/codec_subcall_poc_test.go")
        self.assertEqual(rows[0]["confidence"], "high")
        self.assertEqual(rows[0]["match_method"], "submission-explicit-path")
        self.assertIn("submission_explicit_reference", rows[0]["source_reasons"])
        self.assertTrue(rows[0]["candidate_artifact_exists"])
        self.assertEqual(rows[0]["candidate_path_occurrence"], 1)
        self.assertEqual(rows[0]["candidate_path_specificity"], 1.0)
        self.assertTrue(rows[0]["promotion_ready"])
        self.assertEqual(rows[0]["promotion_blockers"], [])
        self.assertEqual(rows[0]["promotion_gate_version"], "proof-artifact-index-promotion-v1")
        self.assertEqual(rows[0]["promotion_review_status"], "ready")
        self.assertIn("explicit high-confidence", rows[0]["promotion_review_reason"])
        self.assertTrue(rows[0]["accepted_proof_artifact"])
        self.assertEqual(rows[0]["proof_acceptance_status"], "accepted")
        self.assertEqual(rows[0]["proof_acceptance_blockers"], [])
        self.assertEqual(rows[0]["current_workspace_source_refs"], ["audits/dydx/src/codec.go"])
        self.assertIn("concrete_proof_or_harness_evidence", rows[0]["proof_acceptance_reasons"])
        self.assertEqual(rows[0]["generated_at"], summary["generated_at"])
        self.assertEqual(summary["promotion_ready_rows"], 1)
        self.assertEqual(summary["accepted_proof_rows"], 1)
        self.assertEqual(summary["promotion_gate_version"], "proof-artifact-index-promotion-v1")
        self.assertEqual(summary["acceptance_gate_version"], "proof-artifact-index-acceptance-v1")
        self.assertEqual(summary["promotion_blocker_histogram"], {})
        self.assertEqual(summary["acceptance_blocker_histogram"], {})

    def test_explicit_row_missing_source_refs_remains_visible_but_not_accepted(self) -> None:
        self._write_go_proof()
        self._write(
            self.eng / "submissions" / "paste_ready" / "codec-subcall-HIGH.md",
            """
            # Codec subcall cap weakening

            proof_artifact: poc-tests/lead_codec/codec_subcall_poc_test.go
            """,
        )

        summary, rows = self._run()

        self.assertEqual(summary["candidate_rows"], 1)
        self.assertEqual(rows[0]["promotion_ready"], True)
        self.assertFalse(rows[0]["accepted_proof_artifact"])
        self.assertEqual(rows[0]["proof_acceptance_status"], "missing-source")
        self.assertIn("missing_current_workspace_source_refs", rows[0]["proof_acceptance_blockers"])
        self.assertEqual(summary["accepted_proof_rows"], 0)
        self.assertEqual(summary["acceptance_blocker_histogram"]["missing_current_workspace_source_refs"], 1)

    def test_stale_workspace_source_refs_block_acceptance_with_typed_reason(self) -> None:
        self._write_go_proof()
        self._write(
            self.eng / "submissions" / "paste_ready" / "codec-subcall-HIGH.md",
            """
            # Codec subcall cap weakening

            source_refs: audits/spark/src/codec.go:1
            proof_artifact: poc-tests/lead_codec/codec_subcall_poc_test.go
            """,
        )

        summary, rows = self._run()

        self.assertEqual(summary["candidate_rows"], 1)
        self.assertFalse(rows[0]["accepted_proof_artifact"])
        self.assertEqual(rows[0]["source_ref_status"], "stale-workspace")
        self.assertEqual(rows[0]["proof_acceptance_status"], "stale-source")
        self.assertEqual(rows[0]["stale_workspace_source_refs"], ["audits/spark/src/codec.go:1"])
        self.assertIn("stale_workspace_source_refs", rows[0]["proof_acceptance_blockers"])
        self.assertEqual(summary["acceptance_blocker_histogram"]["stale_workspace_source_refs"], 1)

    def test_advisory_only_row_blocks_acceptance_but_stays_indexed(self) -> None:
        source_ref = self._write_current_source_ref()
        self._write_go_proof()
        self._write(
            self.eng / "submissions" / "paste_ready" / "codec-subcall-HIGH.md",
            f"""
            # Codec subcall cap weakening

            This is advisory-only detector telemetry.

            source_refs: {source_ref}
            proof_artifact: poc-tests/lead_codec/codec_subcall_poc_test.go
            """,
        )

        summary, rows = self._run()

        self.assertEqual(summary["candidate_rows"], 1)
        self.assertTrue(rows[0]["advisory_only"])
        self.assertFalse(rows[0]["accepted_proof_artifact"])
        self.assertEqual(rows[0]["proof_acceptance_status"], "advisory")
        self.assertIn("advisory_only", rows[0]["proof_acceptance_blockers"])
        self.assertEqual(summary["acceptance_status_counts"], {"advisory": 1})

    def test_unsafe_explicit_reference_is_skipped(self) -> None:
        self._write(
            self.eng / "submissions" / "paste_ready" / "unsafe.md",
            """
            # Unsafe reference

            poc_path: https://example.invalid/poc_test.go
            """,
        )

        summary, rows = self._run()

        self.assertEqual(summary["candidate_rows"], 0)
        self.assertEqual(summary["skipped_unsafe_refs"], 1)
        self.assertEqual(rows, [])

    def test_token_match_emits_review_only_candidate(self) -> None:
        source_ref = self._write_current_source_ref()
        self._write_go_proof("codec_subcall_regression_test.go")
        self._write(
            self.eng / "submissions" / "paste_ready" / "codec-subcall-HIGH.md",
            f"""
            # Codec subcall cap weakening

            source_refs: {source_ref}
            Body without explicit artifact path.
            """,
        )

        summary, rows = self._run()

        self.assertEqual(summary["candidate_rows"], 1)
        self.assertEqual(rows[0]["match_method"], "submission-artifact-token-overlap")
        self.assertEqual(rows[0]["candidate_proof_path"], "audits/dydx/poc-tests/lead_codec/codec_subcall_regression_test.go")
        self.assertIn(rows[0]["confidence"], {"medium", "low"})
        self.assertIn("codec", rows[0]["token_overlap"])
        self.assertFalse(rows[0]["promotion_ready"])
        self.assertIn("confidence_not_high", rows[0]["promotion_blockers"])
        self.assertIn("match_not_explicit_reference", rows[0]["promotion_blockers"])
        self.assertEqual(rows[0]["promotion_review_status"], "blocked")
        self.assertIn("confidence_not_high", rows[0]["promotion_review_reason"])
        self.assertFalse(rows[0]["accepted_proof_artifact"])
        self.assertEqual(rows[0]["proof_acceptance_status"], "blocked")
        self.assertIn("confidence_not_high", rows[0]["proof_acceptance_blockers"])
        self.assertIn("match_not_explicit_reference", rows[0]["proof_acceptance_blockers"])
        self.assertIn("current_workspace_source_refs", rows[0]["proof_acceptance_reasons"])
        self.assertIn("concrete_proof_or_harness_evidence", rows[0]["proof_acceptance_reasons"])
        self.assertEqual(summary["promotion_blocker_histogram"]["confidence_not_high"], 1)
        self.assertEqual(summary["promotion_blocker_histogram"]["match_not_explicit_reference"], 1)
        self.assertEqual(summary["acceptance_blocker_histogram"]["confidence_not_high"], 1)
        self.assertEqual(summary["acceptance_blocker_histogram"]["match_not_explicit_reference"], 1)

    def test_explicit_high_confidence_path_is_blocked_when_fanout_is_broad(self) -> None:
        self._write(
            self.eng / "poc-tests" / "lead_codec" / "codec_subcall_poc_test.go",
            "package lead_codec\n",
        )
        for idx in range(4):
            self._write(
                self.eng / "submissions" / "paste_ready" / f"codec-subcall-{idx}-HIGH.md",
                """
                # Codec subcall cap weakening

                proof_artifact: poc-tests/lead_codec/codec_subcall_poc_test.go
                """,
            )

        summary, rows = self._run()

        self.assertEqual(summary["candidate_rows"], 4)
        self.assertEqual(summary["promotion_ready_rows"], 0)
        self.assertEqual(rows[0]["candidate_path_occurrence"], 4)
        self.assertEqual(rows[0]["candidate_path_specificity"], 0.25)
        self.assertFalse(rows[0]["promotion_ready"])
        self.assertIn("path_fanout_above_promotion_limit", rows[0]["promotion_blockers"])
        self.assertEqual(summary["promotion_blocker_histogram"]["path_fanout_above_promotion_limit"], 4)

    def test_does_not_mutate_corpus_tag_yaml(self) -> None:
        tag = self.root / "audit" / "corpus_tags" / "tags" / "record.yaml"
        original = "schema_version: auditooor.hackerman_record.v1\nrecord_id: rec-1\n"
        self._write(tag, original)
        self._write(
            self.eng / "poc-tests" / "lead_codec" / "codec_subcall_poc_test.go",
            "package lead_codec\n",
        )
        self._write(
            self.eng / "submissions" / "paste_ready" / "codec-subcall-HIGH.md",
            "proof_artifact: poc-tests/lead_codec/codec_subcall_poc_test.go\n",
        )

        self._run()

        self.assertEqual(tag.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
