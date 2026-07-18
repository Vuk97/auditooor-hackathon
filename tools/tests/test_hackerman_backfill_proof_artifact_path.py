from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-backfill-proof-artifact-path.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_backfill_proof_artifact_path", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanBackfillProofArtifactPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tag_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, name: str, text: str) -> Path:
        path = self.tag_dir / name
        path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
        return path

    def test_backfills_safe_poc_path_from_source_tag(self) -> None:
        self._write(
            "source.yaml",
            """
            verdict_id: sample
            target_repo: example/protocol
            poc_path: poc_execution/sample.log
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-1
            target_repo: example/protocol
            year: 2026
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["updated"], 1)
        self.assertEqual(summary["candidates"][0]["status"], "updated")
        self.assertEqual(summary["candidates"][0]["reason"], "target_repo_match")
        self.assertEqual(summary["candidates"][0]["raw_proof_artifact_path"], "poc_execution/sample.log")
        text = record_path.read_text(encoding="utf-8")
        self.assertIn("proof_artifact_path: poc_execution/sample.log", text)
        self.assertLess(text.index("proof_artifact_path:"), text.index("cross_language_analogues:"))

    def test_skips_absolute_or_url_poc_path(self) -> None:
        self._write(
            "source.yaml",
            """
            target_repo: example/protocol
            poc_path: https://example.com/poc.log
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-1
            target_repo: example/protocol
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["updated"], 0)
        self.assertEqual(summary["skipped_unsafe"], 1)
        self.assertEqual(summary["candidates"][0]["raw_proof_artifact_path"], "https://example.com/poc.log")
        self.assertNotIn("proof_artifact_path:", record_path.read_text(encoding="utf-8"))

    def test_normalizes_home_audits_absolute_poc_path(self) -> None:
        home_poc = Path.home() / "audits" / "dydx" / "poc-tests" / "sample.go"
        self._write(
            "source.yaml",
            f"""
            target_repo: dydxprotocol/v4-chain
            poc_path: {home_poc.as_posix()}
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-1
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["updated"], 1)
        text = record_path.read_text(encoding="utf-8")
        self.assertIn("proof_artifact_path: audits/dydx/poc-tests/sample.go", text)

    def test_normalizes_root_audits_absolute_poc_path(self) -> None:
        self._write(
            "source.yaml",
            """
            target_repo: dydxprotocol/v4-chain
            poc_path: /audits/dydx/poc-tests/sample.go
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-1
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["updated"], 1)
        text = record_path.read_text(encoding="utf-8")
        self.assertIn("proof_artifact_path: audits/dydx/poc-tests/sample.go", text)

    def test_dry_run_reports_without_writing(self) -> None:
        self._write(
            "source.yaml",
            """
            target_repo: example/protocol
            poc_path: poc_execution/sample.log
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-1
            target_repo: example/protocol
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir, dry_run=True)

        self.assertEqual(summary["updated"], 1)
        self.assertEqual(summary["candidates"][0]["status"], "would_update")
        self.assertEqual(summary["candidates"][0]["proof_artifact_path"], "poc_execution/sample.log")
        self.assertNotIn("proof_artifact_path:", record_path.read_text(encoding="utf-8"))

    def test_skips_target_repo_mismatch(self) -> None:
        self._write(
            "source.yaml",
            """
            target_repo: source/protocol
            poc_path: poc_execution/sample.log
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-1
            target_repo: record/protocol
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["updated"], 0)
        self.assertEqual(summary["skipped_target_mismatch"], 1)
        self.assertEqual(summary["candidates"][0]["reason"], "target_repo_mismatch")
        self.assertEqual(summary["candidates"][0]["raw_proof_artifact_path"], "poc_execution/sample.log")
        self.assertNotIn("proof_artifact_path:", record_path.read_text(encoding="utf-8"))

    def test_skips_missing_target_repo_before_writing(self) -> None:
        self._write("source.yaml", "poc_path: poc_execution/sample.log\n")
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-1
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["updated"], 0)
        self.assertEqual(summary["skipped_target_missing"], 1)
        self.assertEqual(summary["candidates"][0]["reason"], "target_repo_missing")
        self.assertNotIn("proof_artifact_path:", record_path.read_text(encoding="utf-8"))

    def test_quoted_schema_version_is_scanned(self) -> None:
        self._write(
            "source.yaml",
            """
            target_repo: example/protocol
            poc_path: poc_execution/sample.log
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: "auditooor.hackerman_record.v1"
            record_id: rec-1
            target_repo: example/protocol
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["updated"], 1)
        self.assertIn("proof_artifact_path: poc_execution/sample.log", record_path.read_text(encoding="utf-8"))

    def test_v1_1_schema_version_is_scanned(self) -> None:
        self._write(
            "source.yaml",
            """
            target_repo: example/protocol
            poc_path: poc_execution/sample.log
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-1
            target_repo: example/protocol
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["scanned_hackerman_records"], 1)
        self.assertEqual(summary["updated"], 1)
        self.assertIn("proof_artifact_path: poc_execution/sample.log", record_path.read_text(encoding="utf-8"))

    def test_schema_alias_is_scanned(self) -> None:
        self._write(
            "source.yaml",
            """
            target_repo: example/protocol
            poc_path: poc_execution/sample.log
            """,
        )
        record_path = self._write(
            "record.yaml",
            """
            # source_tag_file: source.yaml
            schema: auditooor.hackerman_record.v1.1
            record_id: rec-1
            target_repo: example/protocol
            cross_language_analogues: []
            """,
        )

        summary = self.tool.backfill(self.tag_dir)

        self.assertEqual(summary["scanned_hackerman_records"], 1)
        self.assertEqual(summary["updated"], 1)
        self.assertIn("proof_artifact_path: poc_execution/sample.log", record_path.read_text(encoding="utf-8"))


class HackermanCrawlEngagementsTests(unittest.TestCase):
    """Tests for the --crawl-engagements PoC discovery + fuzzy matcher."""

    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.tag_dir = self.root / "tags"
        self.tag_dir.mkdir()
        self.audits = self.root / "audits"
        self.audits.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_tag(self, name: str, text: str) -> Path:
        path = self.tag_dir / name
        path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
        return path

    def _write_sidecar(self, rows: list[dict[str, object]]) -> Path:
        sidecar = self.root / "derived" / "proof_hardening.jsonl"
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        return sidecar

    def _write_submission_resolution_sidecars(
        self,
        *,
        submission_ref: str,
        tag_file: str,
        record_id: str,
    ) -> None:
        derived = self.root / "derived"
        derived.mkdir(parents=True, exist_ok=True)
        detector_row = {
            "source_audit_ref": submission_ref,
            "file_name": tag_file,
            "record_id": record_id,
        }
        exploit_row = {
            "source_audit_ref": submission_ref,
            "tag_file": tag_file,
            "record_id": record_id,
        }
        (derived / "detector_relationship_records.jsonl").write_text(
            json.dumps(detector_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (derived / "exploit_predicates.jsonl").write_text(
            json.dumps(exploit_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _make_engagement(self, name: str) -> Path:
        eng = self.audits / name
        (eng / "submissions" / "paste_ready" / "filed").mkdir(parents=True)
        (eng / "poc-tests").mkdir(parents=True)
        return eng

    def test_crawl_discovers_paste_ready_proof_line(self) -> None:
        eng = self._make_engagement("dydx")
        (eng / "submissions" / "paste_ready" / "filed" / "dydx-affiliate-blocked-CRITICAL.md").write_text(
            "Summary: blocked addr fee redirect on affiliate path.\n"
            "- proof_artifact: poc-tests/lead_affiliate_blocked/affiliate_blocked_test.go - PASS\n",
            encoding="utf-8",
        )
        lead_dir = eng / "poc-tests" / "lead_affiliate_blocked"
        lead_dir.mkdir(parents=True)
        (lead_dir / "affiliate_blocked_test.go").write_text("// poc\n", encoding="utf-8")

        self._write_tag(
            "rec_affiliate.yaml",
            """
            schema_version: auditooor.hackerman_record.v1
            record_id: "dydx-affiliate-blocked-addr-fee-redirect"
            target_repo: dydxprotocol/v4-chain
            target_component: affiliate-keeper.go
            attack_class: affiliate-fee-redirect
            bug_class: blocked-addr-bypass
            year: 2026
            cross_language_analogues: []
            """,
        )

        out_path = self.root / ".auditooor" / "candidates.jsonl"
        summary = self.tool.crawl_engagements(
            self.tag_dir, [eng], out_path=out_path, min_score=0.10
        )

        self.assertEqual(summary["scanned_hackerman_records"], 1)
        self.assertGreaterEqual(summary["matched_records"], 1)
        self.assertTrue(out_path.is_file())
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["record_id"], "dydx-affiliate-blocked-addr-fee-redirect")
        self.assertEqual(row["engagement"], "dydx")
        # Path normalized to audits/<eng>/... never absolute.
        self.assertTrue(row["candidate_proof_path"].startswith("audits/dydx/"))
        self.assertNotIn("/Users/", row["candidate_proof_path"])
        self.assertGreater(row["match_score"], 0.0)
        self.assertIn("candidate_path_occurrence", row)
        self.assertIn("candidate_path_specificity", row)
        self.assertIn("match_confidence_reason", row)
        self.assertEqual(row["match_confidence"], "low")
        self.assertEqual(row["match_confidence_reason"], "score_below_threshold")
        self.assertEqual(row["candidate_path_occurrence"], 1)
        self.assertEqual(row["candidate_path_specificity"], 1.0)
        self.assertFalse(row["promotion_ready"])
        self.assertIn("score_below_threshold", row["promotion_blockers"])

    def test_crawl_discovers_in_tree_poc_test_file(self) -> None:
        eng = self._make_engagement("dydx")
        keeper_dir = eng / "external" / "v4-chain" / "protocol" / "x" / "clob" / "keeper"
        keeper_dir.mkdir(parents=True)
        (keeper_dir / "clob_cross_subaccount_trigger_wash_poc_test.go").write_text(
            "// in-tree poc\n", encoding="utf-8"
        )

        self._write_tag(
            "rec_clob.yaml",
            """
            schema_version: auditooor.hackerman_record.v1
            record_id: "dydx-clob-cross-subaccount-trigger-wash"
            target_repo: dydxprotocol/v4-chain
            target_component: clob-keeper.go
            attack_class: cross-subaccount-trigger-wash
            bug_class: wash-trading
            year: 2026
            cross_language_analogues: []
            """,
        )

        out_path = self.root / ".auditooor" / "candidates.jsonl"
        summary = self.tool.crawl_engagements(
            self.tag_dir, [eng], out_path=out_path, min_score=0.10
        )

        self.assertGreaterEqual(summary["matched_records"], 1)
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["source_artifact"], "in-tree-poc")
        self.assertIn("clob_cross_subaccount", rows[0]["candidate_proof_path"])
        self.assertTrue(rows[0]["candidate_proof_path"].startswith("audits/dydx/"))

    def test_crawl_skips_records_already_having_proof_artifact_path(self) -> None:
        eng = self._make_engagement("dydx")
        lead_dir = eng / "poc-tests" / "lead_affiliate_blocked"
        lead_dir.mkdir(parents=True)
        (lead_dir / "affiliate_blocked_test.go").write_text("// poc\n", encoding="utf-8")

        self._write_tag(
            "rec_existing.yaml",
            """
            schema_version: auditooor.hackerman_record.v1
            record_id: "dydx-affiliate-blocked"
            target_component: affiliate-blocked.go
            attack_class: affiliate
            year: 2026
            proof_artifact_path: audits/dydx/poc-tests/something/existing.go
            cross_language_analogues: []
            """,
        )

        out_path = self.root / ".auditooor" / "candidates.jsonl"
        summary = self.tool.crawl_engagements(
            self.tag_dir, [eng], out_path=out_path, min_score=0.10
        )

        self.assertEqual(summary["skipped_existing"], 1)
        self.assertEqual(summary["matched_records"], 0)

    def test_crawl_dry_run_does_not_write_output(self) -> None:
        eng = self._make_engagement("dydx")
        lead_dir = eng / "poc-tests" / "lead_affiliate_blocked"
        lead_dir.mkdir(parents=True)
        (lead_dir / "affiliate_blocked_test.go").write_text("// poc\n", encoding="utf-8")

        self._write_tag(
            "rec_a.yaml",
            """
            schema_version: auditooor.hackerman_record.v1
            record_id: "dydx-affiliate-blocked"
            target_component: affiliate-blocked.go
            attack_class: affiliate-blocked
            year: 2026
            cross_language_analogues: []
            """,
        )

        out_path = self.root / ".auditooor" / "candidates.jsonl"
        summary = self.tool.crawl_engagements(
            self.tag_dir, [eng], out_path=out_path, min_score=0.10, dry_run=True
        )

        self.assertGreaterEqual(summary["matched_records"], 1)
        self.assertFalse(out_path.exists())
        # Sample preview should still be emitted in summary.
        self.assertGreaterEqual(len(summary["sample_candidates"]), 1)

    def test_crawl_does_not_write_back_to_tag_yaml(self) -> None:
        eng = self._make_engagement("dydx")
        lead_dir = eng / "poc-tests" / "lead_affiliate_blocked"
        lead_dir.mkdir(parents=True)
        (lead_dir / "affiliate_blocked_test.go").write_text("// poc\n", encoding="utf-8")

        tag_path = self._write_tag(
            "rec_a.yaml",
            """
            schema_version: auditooor.hackerman_record.v1
            record_id: "dydx-affiliate-blocked"
            target_component: affiliate-blocked.go
            attack_class: affiliate-blocked
            year: 2026
            cross_language_analogues: []
            """,
        )
        original = tag_path.read_text(encoding="utf-8")

        out_path = self.root / ".auditooor" / "candidates.jsonl"
        self.tool.crawl_engagements(self.tag_dir, [eng], out_path=out_path, min_score=0.10)

        # Hard rule: candidates-only crawler must NOT write back to the tag yaml.
        self.assertEqual(tag_path.read_text(encoding="utf-8"), original)
        self.assertNotIn("proof_artifact_path:", tag_path.read_text(encoding="utf-8"))

    def test_crawl_match_score_distinguishes_high_vs_low_confidence(self) -> None:
        eng = self._make_engagement("dydx")
        # Multi-token-overlap lead.
        good_dir = eng / "poc-tests" / "lead_clob_cross_subaccount_trigger_wash"
        good_dir.mkdir(parents=True)
        (good_dir / "clob_cross_subaccount_trigger_wash_test.go").write_text("// poc\n", encoding="utf-8")
        # Distractor lead.
        bad_dir = eng / "poc-tests" / "lead_unrelated_bridge"
        bad_dir.mkdir(parents=True)
        (bad_dir / "bridge_test.go").write_text("// poc\n", encoding="utf-8")

        self._write_tag(
            "rec_clob.yaml",
            """
            schema_version: auditooor.hackerman_record.v1
            record_id: "dydx-clob-cross-subaccount-trigger-wash"
            target_component: clob-keeper.go
            attack_class: cross-subaccount-trigger-wash
            bug_class: wash-trading
            year: 2026
            cross_language_analogues: []
            """,
        )

        out_path = self.root / ".auditooor" / "candidates.jsonl"
        summary = self.tool.crawl_engagements(
            self.tag_dir, [eng], out_path=out_path,
            min_score=0.10, high_confidence=0.30,
        )
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        # Best match should be the multi-overlap lead (not the bridge distractor).
        self.assertEqual(len(rows), 1)
        self.assertIn("clob_cross_subaccount", rows[0]["candidate_proof_path"])
        self.assertEqual(rows[0]["match_confidence"], "high")
        self.assertTrue(rows[0]["promotion_ready"])
        self.assertEqual(rows[0]["promotion_blockers"], [])
        self.assertEqual(summary["promotion_ready_candidates"], 1)

    def test_crawl_high_confidence_candidate_with_broad_fanout_stays_review_only(self) -> None:
        eng = self._make_engagement("dydx")
        lead_dir = eng / "poc-tests" / "lead_clob_cross_subaccount_trigger_wash"
        lead_dir.mkdir(parents=True)
        (lead_dir / "clob_cross_subaccount_trigger_wash_test.go").write_text("// poc\n", encoding="utf-8")

        for idx in range(4):
            self._write_tag(
                f"rec_clob_{idx}.yaml",
                """
                schema_version: auditooor.hackerman_record.v1
                record_id: "dydx-clob-cross-subaccount-trigger-wash"
                target_component: clob-keeper.go
                attack_class: cross-subaccount-trigger-wash
                bug_class: wash-trading
                year: 2026
                cross_language_analogues: []
                """,
            )

        out_path = self.root / ".auditooor" / "candidates.jsonl"
        summary = self.tool.crawl_engagements(
            self.tag_dir, [eng], out_path=out_path,
            min_score=0.10, high_confidence=0.30,
        )

        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 4)
        self.assertEqual(summary["high_confidence_matches"], 4)
        self.assertEqual(summary["promotion_ready_candidates"], 0)
        self.assertEqual(summary["promotion_blocker_counts"]["path_fanout_above_promotion_limit"], 4)
        self.assertTrue(all(row["match_confidence"] == "high" for row in rows))
        self.assertTrue(all(row["candidate_path_occurrence"] == 4 for row in rows))
        self.assertTrue(all(not row["promotion_ready"] for row in rows))
        self.assertTrue(
            all("path_fanout_above_promotion_limit" in row["promotion_blockers"] for row in rows)
        )

    def test_sidecar_miner_uses_source_ref_and_record_id_for_candidate(self) -> None:
        tag_path = self._write_tag(
            "rec_sidecar.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: "legacy:dydx-hunt-iter-3_dydx-clob-c1-clamp-harness-verdict.md:16a7f0135583"
            target_repo: dydxprotocol/v4-chain
            target_component: clob-keeper.go
            attack_class: clamp-self-match
            year: 2026
            cross_language_analogues: []
            """,
        )
        sidecar = self._write_sidecar(
            [
                {
                    "schema": "auditooor.hackerman_proof_hardening.v1",
                    "record_id": "legacy:dydx-hunt-iter-3_dydx-clob-c1-clamp-harness-verdict.md:16a7f0135583",
                    "source_ref": f"audit/corpus_tags/tags/{tag_path.name}",
                    "proof_artifacts": [
                        "audits/dydx/external/v4-chain/protocol/x/clob/keeper/clamp_self_match_poc_test.go"
                    ],
                    "proof_maturity_score": 2,
                    "evidence_class": "unknown_proof_posture",
                }
            ]
        )

        out_path = self.root / ".auditooor" / "sidecar-candidates.jsonl"
        summary = self.tool.mine_proof_hardening_sidecar(
            self.tag_dir, sidecar, out_path=out_path
        )

        self.assertEqual(summary["candidate_count"], 1)
        self.assertTrue(out_path.is_file())
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["record_yaml"], "rec_sidecar.yaml")
        self.assertEqual(rows[0]["match_method"], "proof-hardening-source-ref-record-id")
        self.assertEqual(rows[0]["match_confidence"], "direct")
        self.assertEqual(
            rows[0]["candidate_proof_path"],
            "audits/dydx/external/v4-chain/protocol/x/clob/keeper/clamp_self_match_poc_test.go",
        )
        self.assertNotIn("proof_artifact_path:", tag_path.read_text(encoding="utf-8"))

    def test_sidecar_miner_normalizes_home_audit_absolute_candidate(self) -> None:
        tag_path = self._write_tag(
            "rec_abs.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-abs
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        proof = Path.home() / "audits" / "dydx" / "poc-tests" / "lead" / "sample_test.go"
        sidecar = self._write_sidecar(
            [
                {
                    "record_id": "rec-abs",
                    "source_ref": tag_path.as_posix(),
                    "proof_artifacts": [proof.as_posix()],
                }
            ]
        )

        out_path = self.root / ".auditooor" / "sidecar-candidates.jsonl"
        summary = self.tool.mine_proof_hardening_sidecar(
            self.tag_dir, sidecar, out_path=out_path
        )

        self.assertEqual(summary["candidate_count"], 1)
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["candidate_proof_path"], "audits/dydx/poc-tests/lead/sample_test.go")

    def test_sidecar_miner_rejects_unsafe_candidate_paths(self) -> None:
        tag_path = self._write_tag(
            "rec_unsafe.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-unsafe
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        sidecar = self._write_sidecar(
            [
                {
                    "record_id": "rec-unsafe",
                    "source_ref": tag_path.as_posix(),
                    "proof_artifacts": ["https://example.com/poc_test.go", "/tmp/poc_test.go"],
                }
            ]
        )

        out_path = self.root / ".auditooor" / "sidecar-candidates.jsonl"
        summary = self.tool.mine_proof_hardening_sidecar(
            self.tag_dir, sidecar, out_path=out_path
        )

        self.assertEqual(summary["candidate_count"], 0)
        self.assertEqual(summary["skipped_unsafe"], 2)
        self.assertEqual(out_path.read_text(encoding="utf-8"), "")

    def test_sidecar_miner_dry_run_does_not_write_output_or_yaml(self) -> None:
        tag_path = self._write_tag(
            "rec_dry.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-dry
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        original = tag_path.read_text(encoding="utf-8")
        sidecar = self._write_sidecar(
            [
                {
                    "record_id": "rec-dry",
                    "source_ref": tag_path.as_posix(),
                    "proof_artifacts": ["audits/dydx/poc-tests/lead/sample_test.go"],
                }
            ]
        )

        out_path = self.root / ".auditooor" / "sidecar-candidates.jsonl"
        summary = self.tool.mine_proof_hardening_sidecar(
            self.tag_dir, sidecar, out_path=out_path, dry_run=True
        )

        self.assertEqual(summary["candidate_count"], 1)
        self.assertEqual(len(summary["sample_candidates"]), 1)
        self.assertFalse(out_path.exists())
        self.assertEqual(tag_path.read_text(encoding="utf-8"), original)

    def test_sidecar_miner_skips_record_id_mismatch(self) -> None:
        tag_path = self._write_tag(
            "rec_mismatch.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-real
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        sidecar = self._write_sidecar(
            [
                {
                    "record_id": "rec-other",
                    "source_ref": tag_path.as_posix(),
                    "proof_artifacts": ["audits/dydx/poc-tests/lead/sample_test.go"],
                }
            ]
        )

        out_path = self.root / ".auditooor" / "sidecar-candidates.jsonl"
        summary = self.tool.mine_proof_hardening_sidecar(
            self.tag_dir, sidecar, out_path=out_path
        )

        self.assertEqual(summary["candidate_count"], 0)
        self.assertEqual(summary["skipped_record_id_mismatch"], 1)

    def test_review_proof_artifact_index_emits_bounded_review_plan_without_yaml_write(self) -> None:
        tag_path = self._write_tag(
            "rec_review.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-review
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        original = tag_path.read_text(encoding="utf-8")
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        rows = [
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": True,
                "promotion_review_status": "ready",
                "promotion_blockers": [],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
                "submission_status": "paste_ready",
            },
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": True,
                "promotion_review_status": "ready",
                "promotion_blockers": [],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/second_test.go",
                "submission_path": "audits/dydx/submissions/paste_ready/second.md",
                "submission_status": "paste_ready",
                "record_yaml": tag_path.name,
                "record_id": "rec-review",
            },
        ]
        index.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        summary = self.tool.review_proof_artifact_index(self.tag_dir, index, out_path=out_path, limit=1)

        self.assertEqual(summary["promotion_ready_rows"], 2)
        self.assertEqual(summary["plan_rows"], 1)
        self.assertEqual(summary["review_required"], 1)
        self.assertEqual(summary["ready_to_apply"], 0)
        self.assertTrue(out_path.is_file())
        plan_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(plan_rows[0]["apply_status"], "review_required")
        self.assertEqual(plan_rows[0]["blockers"], ["needs_record_yaml"])
        self.assertNotIn("proof_artifact_path:", tag_path.read_text(encoding="utf-8"))
        self.assertEqual(tag_path.read_text(encoding="utf-8"), original)

    def test_review_proof_artifact_index_emits_missing_record_import_queue_read_only(self) -> None:
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        rows = [
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": True,
                "promotion_review_status": "ready",
                "promotion_blockers": [],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_artifact_kind": "poc-tests",
                "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
                "submission_status": "paste_ready",
                "submission_title": "Sample theft of yield",
                "promotion_review_reason": "explicit proof artifact reference",
            },
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": True,
                "promotion_review_status": "ready",
                "promotion_blockers": [],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_artifact_kind": "execution-output",
                "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_transcript.txt",
                "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
                "submission_status": "paste_ready",
                "submission_title": "Sample theft of yield",
                "promotion_review_reason": "explicit transcript reference",
            },
        ]
        index.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        queue_path = self.root / ".auditooor" / "missing-record-queue.jsonl"
        summary = self.tool.review_proof_artifact_index(
            self.tag_dir,
            index,
            out_path=out_path,
            missing_record_import_queue_out=queue_path,
        )

        self.assertEqual(summary["ready_to_apply"], 0)
        self.assertEqual(summary["review_required"], 2)
        self.assertEqual(summary["missing_record_import_candidates"], 1)
        self.assertTrue(queue_path.is_file())
        self.assertEqual(list(self.tag_dir.glob("*.yaml")), [])
        plan_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(all(row["missing_record_import_candidate"] for row in plan_rows))
        queue_rows = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(queue_rows), 1)
        self.assertEqual(queue_rows[0]["schema"], self.tool.MISSING_RECORD_IMPORT_QUEUE_SCHEMA)
        self.assertEqual(queue_rows[0]["suggested_source_audit_ref"], "paste_ready/sample.md")
        self.assertEqual(queue_rows[0]["candidate_count"], 2)
        self.assertEqual(queue_rows[0]["blockers"], ["needs_record_yaml"])
        self.assertIn("no_yaml_write_performed", queue_rows[0]["safety_flags"])

    def test_review_proof_artifact_index_does_not_queue_existing_record_yaml(self) -> None:
        tag_path = self._write_tag(
            "rec_queue_skip.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-queue-skip
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        index.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "promotion_ready": True,
                    "promotion_review_status": "ready",
                    "promotion_blockers": [],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                    "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
                    "submission_status": "paste_ready",
                    "record_yaml": tag_path.name,
                    "record_id": "rec-queue-skip",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        queue_path = self.root / ".auditooor" / "missing-record-queue.jsonl"
        summary = self.tool.review_proof_artifact_index(
            self.tag_dir,
            index,
            out_path=out_path,
            missing_record_import_queue_out=queue_path,
        )

        self.assertEqual(summary["ready_to_apply"], 1)
        self.assertEqual(summary["missing_record_import_candidates"], 0)
        self.assertTrue(queue_path.is_file())
        self.assertEqual(queue_path.read_text(encoding="utf-8"), "")

    def test_review_proof_artifact_index_marks_exact_record_yaml_ready_to_apply(self) -> None:
        tag_path = self._write_tag(
            "rec_apply.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-apply
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        index.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "promotion_ready": True,
                    "promotion_review_status": "ready",
                    "promotion_blockers": [],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                    "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
                    "submission_status": "paste_ready",
                    "record_yaml": tag_path.name,
                    "record_id": "rec-apply",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        summary = self.tool.review_proof_artifact_index(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["ready_to_apply"], 1)
        plan_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(plan_rows[0]["apply_status"], "ready_to_apply")
        self.assertEqual(plan_rows[0]["action"], "insert_proof_artifact_path")

    def test_review_proof_artifact_index_auto_resolves_submission_ref_ready_to_apply(self) -> None:
        tag_path = self._write_tag(
            "rec_auto.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-auto
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        self._write_submission_resolution_sidecars(
            submission_ref="paste_ready/sample.md",
            tag_file=tag_path.name,
            record_id="rec-auto",
        )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "promotion_ready": True,
                    "promotion_review_status": "ready",
                    "promotion_blockers": [],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                    "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
                    "submission_status": "paste_ready",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        summary = self.tool.review_proof_artifact_index(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["ready_to_apply"], 1)
        self.assertEqual(summary["auto_resolved_rows"], 1)
        self.assertEqual(summary["auto_resolved_unique_submission_refs"], 1)
        plan_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(plan_rows[0]["apply_status"], "ready_to_apply")
        self.assertEqual(plan_rows[0]["record_yaml"], tag_path.name)
        self.assertEqual(plan_rows[0]["record_id"], "rec-auto")
        self.assertTrue(plan_rows[0]["record_resolution_source"].startswith("derived_submission_ref:"))

    def test_review_proof_artifact_index_auto_resolve_reports_existing_proof(self) -> None:
        tag_path = self._write_tag(
            "rec_existing.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-existing
            target_repo: dydxprotocol/v4-chain
            proof_artifact_path: audits/dydx/poc-tests/lead/existing_test.go
            cross_language_analogues: []
            """,
        )
        self._write_submission_resolution_sidecars(
            submission_ref="paste_ready/existing.md",
            tag_file=tag_path.name,
            record_id="rec-existing",
        )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "promotion_ready": True,
                    "promotion_review_status": "ready",
                    "promotion_blockers": [],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/dydx/poc-tests/lead/new_test.go",
                    "submission_path": "audits/dydx/submissions/paste_ready/existing.md",
                    "submission_status": "paste_ready",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        summary = self.tool.review_proof_artifact_index(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["already_has_proof_artifact_path"], 1)
        plan_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(plan_rows[0]["apply_status"], "already_has_proof_artifact_path")
        self.assertEqual(
            plan_rows[0]["existing_proof_artifact_path"],
            "audits/dydx/poc-tests/lead/existing_test.go",
        )

    def test_review_proof_artifact_index_blocks_multiple_candidates_for_same_auto_resolved_yaml(self) -> None:
        tag_path = self._write_tag(
            "rec_ambiguous.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-ambiguous
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        self._write_submission_resolution_sidecars(
            submission_ref="paste_ready/ambiguous.md",
            tag_file=tag_path.name,
            record_id="rec-ambiguous",
        )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": True,
                "promotion_review_status": "ready",
                "promotion_blockers": [],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/one_test.go",
                "submission_path": "audits/dydx/submissions/paste_ready/ambiguous.md",
                "submission_status": "paste_ready",
            },
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": True,
                "promotion_review_status": "ready",
                "promotion_blockers": [],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/two_test.go",
                "submission_path": "audits/dydx/submissions/paste_ready/ambiguous.md",
                "submission_status": "paste_ready",
            },
        ]
        index.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        summary = self.tool.review_proof_artifact_index(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["blocked"], 2)
        self.assertEqual(summary["blocker_counts"]["multiple_candidate_proof_paths_for_record_yaml"], 2)
        plan_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual({row["apply_status"] for row in plan_rows}, {"blocked"})
        self.assertTrue(
            all("multiple_candidate_proof_paths_for_record_yaml" in row["blockers"] for row in plan_rows)
        )

    def test_review_proof_artifact_index_can_explain_blocked_index_rows(self) -> None:
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        rows = [
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": False,
                "promotion_review_status": "blocked",
                "promotion_blockers": ["confidence_not_high", "match_not_explicit_reference"],
                "confidence": "medium",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                "submission_path": "audits/dydx/submissions/paste_ready/sample.md",
                "submission_status": "paste_ready",
                "submission_title": "Sample finding",
            }
        ]
        index.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

        out_path = self.root / ".auditooor" / "promotion-plan.jsonl"
        default_summary = self.tool.review_proof_artifact_index(self.tag_dir, index, out_path=out_path)
        self.assertEqual(default_summary["plan_rows"], 0)

        summary = self.tool.review_proof_artifact_index(
            self.tag_dir,
            index,
            out_path=out_path,
            include_blocked_index_rows=True,
        )

        self.assertEqual(summary["promotion_ready_rows"], 0)
        self.assertEqual(summary["plan_rows"], 1)
        self.assertEqual(summary["not_promotable"], 1)
        self.assertEqual(summary["blocker_counts"]["promotion_ready_not_true"], 1)
        self.assertEqual(summary["blocker_counts"]["confidence_not_high"], 1)
        self.assertEqual(summary["blocker_counts"]["match_not_explicit_reference"], 1)
        plan_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(plan_rows[0]["apply_status"], "not_promotable")
        self.assertEqual(plan_rows[0]["action"], "none")
        self.assertIn("promotion_ready_not_true", plan_rows[0]["blockers"])
        self.assertIn("match_not_explicit_reference", plan_rows[0]["blockers"])
        self.assertFalse(plan_rows[0]["source_index_promotion_ready"])
        self.assertEqual(
            plan_rows[0]["source_index_promotion_blockers"],
            ["confidence_not_high", "match_not_explicit_reference"],
        )

    def test_status_only_blocker_review_emits_report_only_safe_subset(self) -> None:
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        rows = [
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": False,
                "promotion_review_status": "blocked",
                "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                "confidence": "high",
                "confidence_score": 1.0,
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 2,
                "candidate_artifact_kind": "poc-tests",
                "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                "submission_path": "audits/dydx/submissions/packaged/sample.md",
                "submission_status": "packaged",
                "submission_title": "Sample finding",
                "promotion_review_reason": "blocked: submission_status_not_paste_ready_or_filed",
                "source_reasons": ["submission_explicit_reference"],
            },
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": False,
                "promotion_review_status": "blocked",
                "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/root_test.go",
                "submission_path": "audits/dydx/submissions/AUDIT_COMPLETION_STATUS.md",
                "submission_status": "root",
            },
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": False,
                "promotion_review_status": "blocked",
                "promotion_blockers": ["submission_status_not_paste_ready_or_filed", "confidence_not_high"],
                "confidence": "medium",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/medium_test.go",
                "submission_path": "audits/dydx/submissions/packaged/medium.md",
                "submission_status": "packaged",
            },
        ]
        index.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

        out_path = self.root / ".auditooor" / "status-only-review.jsonl"
        summary = self.tool.status_only_blocker_review(index, out_path=out_path)

        self.assertEqual(summary["exact_status_only_rows"], 2)
        self.assertEqual(summary["eligible_rows"], 1)
        self.assertEqual(summary["rows_written"], 1)
        self.assertEqual(summary["by_status"], {"packaged": 1})
        self.assertEqual(summary["rejected_reasons"]["submission_status_not_in_review_set"], 1)
        self.assertEqual(summary["rejected_reasons"]["not_exact_status_only_blocker"], 1)
        rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["schema"], self.tool.STATUS_ONLY_REVIEW_SCHEMA)
        self.assertTrue(rows[0]["status_only_blocker"])
        self.assertEqual(rows[0]["recommended_action"], "manual_status_reconciliation")
        self.assertIn("Report-only", rows[0]["safety_note"])

    def test_status_only_blocker_review_dry_run_does_not_write(self) -> None:
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        index.write_text(
            json.dumps(
                {
                    "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                    "submission_path": "audits/dydx/submissions/ready/sample.md",
                    "submission_status": "ready",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "status-only-review.jsonl"
        summary = self.tool.status_only_blocker_review(index, out_path=out_path, dry_run=True)

        self.assertEqual(summary["eligible_rows"], 1)
        self.assertEqual(summary["rows_written"], 0)
        self.assertFalse(out_path.exists())

    def test_status_only_reconciliation_queue_groups_missing_and_resolved_records_without_mutation(self) -> None:
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True)
        resolved_record = self._write_tag(
            "resolved.yaml",
            """
            schema_version: auditooor.hackerman_record.v1
            record_id: rec-resolved
            target_repo: dydxprotocol/v4-chain
            year: 2026
            cross_language_analogues: []
            """,
        )
        derived = self.tag_dir.parent / "derived"
        derived.mkdir(parents=True, exist_ok=True)
        (derived / "detector_relationship_records.jsonl").write_text(
            json.dumps(
                {
                    "source_audit_ref": "ready/sample.md",
                    "tag_file": "resolved.yaml",
                    "record_id": "rec-resolved",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        rows = [
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": False,
                "promotion_review_status": "blocked",
                "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                "confidence": "high",
                "confidence_score": 1.0,
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_artifact_kind": "execution-output",
                "candidate_proof_path": "audits/dydx/poc-tests/lead/sample.log",
                "submission_path": "audits/dydx/submissions/ready/sample.md",
                "submission_status": "ready",
                "submission_title": "Ready sample",
                "promotion_review_reason": "blocked: submission_status_not_paste_ready_or_filed",
                "source_reasons": ["submission_explicit_reference"],
            },
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": False,
                "promotion_review_status": "blocked",
                "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_artifact_kind": "test-file",
                "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                "submission_path": "audits/dydx/submissions/submitted/missing.md",
                "submission_status": "submitted",
                "submission_title": "Missing record sample",
            },
            {
                "schema": "auditooor.hackerman_proof_artifact_index.v1",
                "promotion_ready": False,
                "promotion_review_status": "blocked",
                "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                "confidence": "high",
                "candidate_artifact_exists": True,
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/packaged.log",
                "submission_path": "audits/dydx/submissions/packaged/packaged.md",
                "submission_status": "packaged",
                "submission_title": "Packaged sample",
            },
        ]
        index.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

        out_path = self.root / ".auditooor" / "status-only-reconciliation.jsonl"
        summary = self.tool.status_only_reconciliation_queue(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["queue_rows"], 3)
        self.assertEqual(summary["candidate_count"], 3)
        self.assertEqual(
            summary["by_reconciliation_status"],
            {
                "record_creation_candidate": 1,
                "record_resolved_needs_owner_confirmation": 1,
                "status_not_final": 1,
            },
        )
        queue_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        resolved = next(row for row in queue_rows if row["submission_ref"] == "ready/sample.md")
        self.assertFalse(resolved["mutation_allowed"])
        self.assertEqual(resolved["record_yaml"], "resolved.yaml")
        self.assertEqual(resolved["record_id"], "rec-resolved")
        self.assertEqual(resolved["reconciliation_status"], "record_resolved_needs_owner_confirmation")
        missing = next(row for row in queue_rows if row["submission_ref"] == "submitted/missing.md")
        self.assertEqual(missing["reconciliation_status"], "record_creation_candidate")
        packaged = next(row for row in queue_rows if row["submission_ref"] == "packaged/packaged.md")
        self.assertEqual(packaged["recommended_action"], "wait_for_paste_ready_or_owner_confirmation")
        self.assertNotIn("proof_artifact_path:", resolved_record.read_text(encoding="utf-8"))

    def test_status_only_reconciliation_resolves_submission_derived_ref_alias_without_mutation(self) -> None:
        tag_path = self._write_tag(
            "polymarket_r77.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-polymarket-r77
            source_audit_ref: submission-derived:polymarket:submitted/R77_archive/R77-08.md
            target_repo: polymarket/protocol
            proof_artifact_path: audits/polymarket/pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol
            cross_language_analogues: []
            """,
        )
        self._write_submission_resolution_sidecars(
            submission_ref="submission-derived:polymarket:submitted/R77_archive/R77-08.md",
            tag_file=tag_path.name,
            record_id="rec-polymarket-r77",
        )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "promotion_ready": False,
                    "promotion_review_status": "blocked",
                    "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_artifact_kind": "foundry-test",
                    "candidate_proof_path": "audits/polymarket/pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol",
                    "submission_path": "audits/polymarket/submissions/submitted/R77_archive/R77-08.md",
                    "submission_status": "submitted",
                    "submission_title": "R77 unflag race",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "status-only-reconciliation.jsonl"
        summary = self.tool.status_only_reconciliation_queue(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["by_reconciliation_status"], {"record_resolved_needs_owner_confirmation": 1})
        queue_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(queue_rows[0]["submission_ref"], "submitted/R77_archive/R77-08.md")
        self.assertEqual(queue_rows[0]["record_yaml"], tag_path.name)
        self.assertEqual(queue_rows[0]["record_id"], "rec-polymarket-r77")
        self.assertTrue(queue_rows[0]["record_resolution_source"].startswith("derived_submission_ref:"))
        self.assertFalse(queue_rows[0]["mutation_allowed"])
        self.assertIn("manual_record_owner_confirmation_required", queue_rows[0]["safety_flags"])

    def test_status_only_reconciliation_resolves_existing_record_by_unique_proof_path_suffix(self) -> None:
        tag_path = self._write_tag(
            "base_fn2.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-base-fn2
            target_repo: reserve-protocol/protocol
            proof_artifact_path: test/FN2_PoC.t.sol
            cross_language_analogues: []
            """,
        )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "promotion_ready": False,
                    "promotion_review_status": "blocked",
                    "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_artifact_kind": "foundry-test",
                    "candidate_proof_path": (
                        "audits/base-azul/differential_fuzz/ws_b_solidity_invariant/test/FN2_PoC.t.sol"
                    ),
                    "submission_path": "audits/base-azul/submissions/ready/FN2-READY.md",
                    "submission_status": "ready",
                    "submission_title": "FN2 ready",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "status-only-reconciliation.jsonl"
        summary = self.tool.status_only_reconciliation_queue(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["by_reconciliation_status"], {"record_resolved_needs_owner_confirmation": 1})
        queue_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(queue_rows[0]["record_yaml"], tag_path.name)
        self.assertEqual(queue_rows[0]["record_id"], "rec-base-fn2")
        self.assertTrue(queue_rows[0]["record_resolution_source"].startswith("derived_proof_artifact_path:"))
        self.assertFalse(queue_rows[0]["mutation_allowed"])

    def test_status_only_reconciliation_does_not_resolve_ambiguous_proof_path_suffix(self) -> None:
        for idx in range(2):
            self._write_tag(
                f"ambiguous_{idx}.yaml",
                f"""
                schema_version: auditooor.hackerman_record.v1.1
                record_id: rec-ambiguous-{idx}
                target_repo: reserve-protocol/protocol
                proof_artifact_path: test/FN2_PoC.t.sol
                cross_language_analogues: []
                """,
            )
        index = self.root / "derived" / "proof_artifact_index.jsonl"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_proof_artifact_index.v1",
                    "promotion_ready": False,
                    "promotion_review_status": "blocked",
                    "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                    "confidence": "high",
                    "candidate_artifact_exists": True,
                    "candidate_path_occurrence": 1,
                    "candidate_artifact_kind": "foundry-test",
                    "candidate_proof_path": (
                        "audits/base-azul/differential_fuzz/ws_b_solidity_invariant/test/FN2_PoC.t.sol"
                    ),
                    "submission_path": "audits/base-azul/submissions/ready/FN2-READY.md",
                    "submission_status": "ready",
                    "submission_title": "FN2 ready",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        out_path = self.root / ".auditooor" / "status-only-reconciliation.jsonl"
        summary = self.tool.status_only_reconciliation_queue(self.tag_dir, index, out_path=out_path)

        self.assertEqual(summary["by_reconciliation_status"], {"record_creation_candidate": 1})
        queue_rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(queue_rows[0]["record_yaml"], "")
        self.assertEqual(queue_rows[0]["record_resolution"], "needs_record_yaml")

    def test_status_only_resolved_promotion_review_emits_confirm_gated_plan_without_mutation(self) -> None:
        tag_path = self._write_tag(
            "resolved_ready.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-resolved-ready
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        reconciliation = self.root / ".auditooor" / "status-only-reconciliation.jsonl"
        reconciliation.parent.mkdir(parents=True, exist_ok=True)
        reconciliation.write_text(
            json.dumps(
                {
                    "schema": self.tool.STATUS_ONLY_RECONCILIATION_SCHEMA,
                    "queue_key": "ready/sample.md",
                    "mutation_allowed": False,
                    "reconciliation_status": "record_resolved_needs_owner_confirmation",
                    "engagement": "dydx",
                    "submission_path": "audits/dydx/submissions/ready/sample.md",
                    "submission_status": "ready",
                    "submission_title": "Ready sample",
                    "record_yaml": tag_path.name,
                    "record_id": "rec-resolved-ready",
                    "record_resolution": "record_yaml",
                    "record_resolution_source": "derived_submission_ref:detector_relationship_records.jsonl",
                    "proof_artifact_candidates": [
                        {
                            "candidate_proof_path": "audits/dydx/poc-tests/lead/sample.log",
                            "raw_candidate_proof_path": "audits/dydx/poc-tests/lead/sample.log",
                            "candidate_artifact_kind": "execution-output",
                            "candidate_path_occurrence": 1,
                            "promotion_review_reason": "status-only candidate",
                        }
                    ],
                    "candidate_count": 1,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        plan = self.root / ".auditooor" / "proof_artifact_promotion_review_status_only_resolved.jsonl"
        summary = self.tool.status_only_resolved_promotion_review(self.tag_dir, reconciliation, out_path=plan)

        self.assertEqual(summary["resolved_record_rows"], 1)
        self.assertEqual(summary["plan_rows"], 1)
        self.assertEqual(summary["ready_to_apply"], 1)
        self.assertEqual(summary["rows_written"], 1)
        rows = [json.loads(line) for line in plan.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["schema"], self.tool.PROMOTION_PLAN_SCHEMA)
        self.assertEqual(rows[0]["source"], "status_only_reconciliation_resolved_record")
        self.assertEqual(rows[0]["apply_status"], "ready_to_apply")
        self.assertEqual(rows[0]["action"], "insert_proof_artifact_path")
        self.assertTrue(rows[0]["owner_confirmation_required"])
        self.assertFalse(rows[0]["safe_to_auto_apply"])
        self.assertEqual(rows[0]["candidate_proof_path"], "audits/dydx/poc-tests/lead/sample.log")
        self.assertNotIn("proof_artifact_path:", tag_path.read_text(encoding="utf-8"))

    def test_status_only_resolved_promotion_review_blocks_multiple_candidate_paths(self) -> None:
        tag_path = self._write_tag(
            "resolved_multi.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-resolved-multi
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        reconciliation = self.root / ".auditooor" / "status-only-reconciliation.jsonl"
        reconciliation.parent.mkdir(parents=True, exist_ok=True)
        reconciliation.write_text(
            json.dumps(
                {
                    "schema": self.tool.STATUS_ONLY_RECONCILIATION_SCHEMA,
                    "queue_key": "ready/multi.md",
                    "mutation_allowed": False,
                    "reconciliation_status": "record_resolved_needs_owner_confirmation",
                    "engagement": "dydx",
                    "submission_path": "audits/dydx/submissions/ready/multi.md",
                    "submission_status": "ready",
                    "record_yaml": tag_path.name,
                    "record_id": "rec-resolved-multi",
                    "record_resolution": "record_yaml",
                    "proof_artifact_candidates": [
                        {
                            "candidate_proof_path": "audits/dydx/poc-tests/lead/a.log",
                            "candidate_path_occurrence": 1,
                        },
                        {
                            "candidate_proof_path": "audits/dydx/poc-tests/lead/b.log",
                            "candidate_path_occurrence": 1,
                        },
                    ],
                    "candidate_count": 2,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        plan = self.root / ".auditooor" / "proof_artifact_promotion_review_status_only_resolved.jsonl"
        summary = self.tool.status_only_resolved_promotion_review(self.tag_dir, reconciliation, out_path=plan)

        self.assertEqual(summary["ready_to_apply"], 0)
        self.assertEqual(summary["blocked"], 1)
        rows = [json.loads(line) for line in plan.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["apply_status"], "blocked")
        self.assertEqual(rows[0]["action"], "manual_review")
        self.assertIn("multiple_candidate_proof_paths_for_reconciliation_row", rows[0]["blockers"])
        self.assertNotIn("proof_artifact_path:", tag_path.read_text(encoding="utf-8"))

    def test_apply_promotion_review_plan_requires_confirmation_and_supports_dry_run(self) -> None:
        tag_path = self._write_tag(
            "rec_confirm.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-confirm
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        plan = self.root / ".auditooor" / "promotion-plan.jsonl"
        plan.parent.mkdir(parents=True)
        plan.write_text(
            json.dumps(
                {
                    "schema": self.tool.PROMOTION_PLAN_SCHEMA,
                    "action": "insert_proof_artifact_path",
                    "apply_status": "ready_to_apply",
                    "record_yaml": tag_path.name,
                    "record_id": "rec-confirm",
                    "candidate_path_occurrence": 1,
                    "candidate_proof_path": "audits/dydx/poc-tests/lead/sample_test.go",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        no_confirm = self.tool.apply_promotion_review_plan(self.tag_dir, plan)
        self.assertEqual(no_confirm["updated"], 0)
        self.assertFalse(no_confirm["confirmed"])

        dry_run = self.tool.apply_promotion_review_plan(self.tag_dir, plan, confirm=True, dry_run=True)
        self.assertEqual(dry_run["updated"], 1)
        self.assertNotIn("proof_artifact_path:", tag_path.read_text(encoding="utf-8"))

    def test_apply_promotion_review_plan_writes_only_ready_basename_yaml(self) -> None:
        safe_tag = self._write_tag(
            "rec_safe.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-safe
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        unsafe_tag = self._write_tag(
            "rec_unsafe_plan.yaml",
            """
            schema_version: auditooor.hackerman_record.v1.1
            record_id: rec-unsafe-plan
            target_repo: dydxprotocol/v4-chain
            cross_language_analogues: []
            """,
        )
        plan = self.root / ".auditooor" / "promotion-plan.jsonl"
        plan.parent.mkdir(parents=True)
        rows = [
            {
                "schema": self.tool.PROMOTION_PLAN_SCHEMA,
                "action": "insert_proof_artifact_path",
                "apply_status": "ready_to_apply",
                "record_yaml": "../outside.yaml",
                "record_id": "rec-unsafe-plan",
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/bad_test.go",
            },
            {
                "schema": self.tool.PROMOTION_PLAN_SCHEMA,
                "action": "insert_proof_artifact_path",
                "apply_status": "ready_to_apply",
                "record_yaml": safe_tag.name,
                "record_id": "rec-safe",
                "candidate_path_occurrence": 1,
                "candidate_proof_path": "audits/dydx/poc-tests/lead/good_test.go",
            },
        ]
        plan.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

        summary = self.tool.apply_promotion_review_plan(self.tag_dir, plan, confirm=True, limit=10)

        self.assertEqual(summary["updated"], 1)
        self.assertEqual(summary["skipped"]["record_yaml_not_basename"], 1)
        self.assertIn("proof_artifact_path: audits/dydx/poc-tests/lead/good_test.go", safe_tag.read_text(encoding="utf-8"))
        self.assertNotIn("proof_artifact_path:", unsafe_tag.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
