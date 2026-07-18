#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "phase-b-e-measurement-report.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("phase_b_e_measurement_report", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")
    return path


class PhaseBEMeasurementReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def _phase_e_row(
        self,
        *,
        pair_id: str,
        engagement_id: str,
        cohort: str,
        metrics: dict,
        evidence_paths: list[str] | None = None,
        **overrides: object,
    ) -> dict:
        row = {
            "schema": self.tool.PHASE_E_ROW_SCHEMA,
            "measurement_window_id": "phase-e-window-test",
            "engagement_id": engagement_id,
            "pair_id": pair_id,
            "cohort": cohort,
            "outcome_observed_at_utc": "2026-06-01T00:00:00Z",
            "metrics": metrics,
            "evidence_paths": evidence_paths
            if evidence_paths is not None
            else [f"reports/test/{engagement_id}/{pair_id}-{cohort}.json"],
        }
        row.update(overrides)
        return row

    def _evidence(self, root: Path, *, pair_id: str, engagement_id: str, cohort: str) -> str:
        path = root / "evidence" / engagement_id / f"{pair_id}-{cohort}.json"
        return str(write_json(
            path,
            {
                "engagement_id": engagement_id,
                "pair_id": pair_id,
                "cohort": cohort,
            },
        ))

    def _p1_passing(self, root: Path) -> Path:
        return write_json(
            root / "p1.json",
            {
                "schema": "auditooor.p1_candidate_triage_dogfood.v2",
                "summary": {
                    "indexed_invariant_count": 502,
                    "no_draft_or_submission_edits": True,
                    "states": {"accepted": 3, "blocked": 13, "cited": 0, "no-match": 0, "suggested": 0},
                },
                "candidate_rows": [
                    {"candidate_id": "a", "state": "accepted"},
                    {"candidate_id": "b", "state": "accepted"},
                    {"candidate_id": "c", "state": "accepted"},
                ],
            },
        )

    def _p3(self, root: Path) -> Path:
        return write_json(
            root / "p3.json",
            {
                "schema": "auditooor.p3_tp_poc_pass_measure.v2",
                "summary": {
                    "candidate_count": 5,
                    "tp_evidence_count": 3,
                    "poc_pass_count": 3,
                    "semantic_pattern_attributed_candidate_count": 3,
                    "tp_poc_pass_rate": 1.0,
                    "tp_poc_pass_rate_state": "computed",
                    "unattributed_poc_pass_count": 0,
                    "unknown_unattributed_tp_evidence_count": 0,
                },
            },
        )

    def _prqs(self, root: Path) -> Path:
        return write_json(
            root / "prqs.json",
            {
                "schema": "auditooor.hb_prqs_comparator_matched_cohort.v1",
                "gate1_prqs_state": "decisive",
                "verdict": "decisive_prqs_no_regression",
                "comparator": {
                    "matched_pair_count": 6,
                    "cohort_a": {"average_score": 44.0},
                    "cohort_b": {"average_score": 30.167},
                    "average_delta_a_minus_b": 13.833,
                    "max_pair_regression_drop_points": 0,
                    "pairs_exceeding_regression_limit": [],
                },
            },
        )

    def test_phase_b_reports_suggested_only_p1_as_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p1 = write_json(
                root / "p1.json",
                {
                    "schema": "auditooor.p1_candidate_triage_dogfood.v2",
                    "summary": {
                        "indexed_invariant_count": 52,
                        "invariant_quality_source": "audited_primary",
                        "include_extracted_broad": False,
                        "no_draft_or_submission_edits": True,
                        "states": {"accepted": 0, "blocked": 1, "cited": 0, "no-match": 0, "suggested": 3},
                    },
                    "candidate_rows": [
                        {"candidate_id": "a", "state": "suggested"},
                        {"candidate_id": "b", "state": "suggested"},
                        {"candidate_id": "c", "state": "suggested"},
                        {"candidate_id": "d", "state": "blocked"},
                    ],
                },
            )
            out = self.tool.phase_b_metrics(p1_path=p1, p3_path=self._p3(root), prqs_path=self._prqs(root))
        self.assertEqual(out["p1_citation_rate"]["verdict"], "fail")
        self.assertEqual(out["p1_citation_rate"]["strict_draft_citation_rate_pct"], 0.0)
        self.assertEqual(out["p1_citation_rate"]["accepted_or_cited_grounding_rate_pct"], 0.0)
        self.assertEqual(out["p1_citation_rate"]["suggested_only_rate_pct"], 100.0)
        self.assertEqual(out["p3_tp_poc_pass"]["verdict"], "pass")
        self.assertEqual(out["prqs_regression"]["verdict"], "pass")
        self.assertIn("p1_current_grounding_below_gate_target", out["blockers"])

    def test_phase_b_accepts_local_review_grounding_without_draft_citation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p1 = self._p1_passing(root)
            out = self.tool.phase_b_metrics(p1_path=p1, p3_path=self._p3(root), prqs_path=self._prqs(root))
        self.assertEqual(out["gate_status"], "passed_all_metrics")
        self.assertEqual(out["p1_citation_rate"]["strict_draft_citation_rate_pct"], 0.0)
        self.assertEqual(out["p1_citation_rate"]["accepted_or_cited_grounding_rate_pct"], 100.0)
        self.assertTrue(out["advance_allowed"])

    def test_summary_keeps_phase_b_pass_separate_from_phase_e_no_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            args = type("Args", (), {
                "p1_triage": str(self._p1_passing(root)),
                "p3_measurement": str(self._p3(root)),
                "prqs_comparator": str(self._prqs(root)),
                "phase_e_rows": None,
            })()
            summary = self.tool.build_summary(args)
        self.assertEqual(summary["phase_b_gate"]["gate_status"], "passed_all_metrics")
        self.assertTrue(summary["phase_b_gate"]["advance_allowed"])
        phase_e = summary["phase_e_ab_dogfood"]
        self.assertEqual(phase_e["verdict"], "insufficient_phase_e_data_prqs_proxy_only")
        self.assertEqual(
            phase_e["production_readiness_status"],
            "blocked_missing_future_matched_ab_engagement_rows",
        )
        self.assertIn("phase_e_requires_4_future_matched_engagements", phase_e["blockers"])
        self.assertIn("no_phase_e_ab_outcome_rows_present", phase_e["blockers"])

    def test_phase_e_without_rows_is_prqs_proxy_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = self.tool.phase_e_measurement(rows_path=None, prqs_path=self._prqs(root))
        self.assertEqual(out["verdict"], "insufficient_phase_e_data_prqs_proxy_only")
        self.assertEqual(out["observed"]["valid_matched_pair_count"], 0)
        self.assertEqual(out["prqs_dogfood_proxy"]["matched_pair_count"], 6)
        self.assertIn("no_phase_e_ab_outcome_rows_present", out["blockers"])

    def test_phase_e_computes_weighted_composite_for_four_matched_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows: list[dict] = []
            for idx in range(4):
                pair = f"pair-{idx}"
                rows.append(self._phase_e_row(
                    pair_id=pair,
                    engagement_id=f"eng-{idx}",
                    cohort="A",
                    metrics={"ppe": 1.0, "frph": 0.5, "prqs": 80, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(root, pair_id=pair, engagement_id=f"eng-{idx}", cohort="A")
                    ],
                ))
                rows.append(self._phase_e_row(
                    pair_id=pair,
                    engagement_id=f"eng-{idx}",
                    cohort="B",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 60, "supporting": 0.4},
                    evidence_paths=[
                        self._evidence(root, pair_id=pair, engagement_id=f"eng-{idx}", cohort="B")
                    ],
                ))
            out = self.tool.phase_e_measurement(
                rows_path=write_jsonl(root / "phase_e_rows.jsonl", rows),
                prqs_path=self._prqs(root),
            )
        self.assertEqual(out["verdict"], "phase_e_measurement_ready")
        self.assertEqual(out["production_readiness_status"], "eligible_for_production_readiness_review")
        self.assertEqual(out["observed"]["valid_matched_pair_count"], 4)
        self.assertEqual(out["observed"]["valid_matched_ab_row_count"], 8)
        self.assertAlmostEqual(out["observed"]["average_composite_delta_a_minus_b"], 0.22)
        self.assertEqual(out["blockers"], [])

    def test_phase_e_requires_distinct_future_engagements_not_just_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows: list[dict] = []
            for idx in range(4):
                pair = f"pair-{idx}"
                rows.append(self._phase_e_row(
                    pair_id=pair,
                    engagement_id="eng-same",
                    cohort="A",
                    metrics={"ppe": 1.0, "frph": 0.5, "prqs": 80, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(root, pair_id=pair, engagement_id="eng-same", cohort="A")
                    ],
                ))
                rows.append(self._phase_e_row(
                    pair_id=pair,
                    engagement_id="eng-same",
                    cohort="B",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 60, "supporting": 0.4},
                    evidence_paths=[
                        self._evidence(root, pair_id=pair, engagement_id="eng-same", cohort="B")
                    ],
                ))
            out = self.tool.phase_e_measurement(
                rows_path=write_jsonl(root / "phase_e_rows.jsonl", rows),
                prqs_path=self._prqs(root),
            )
        self.assertEqual(out["verdict"], "insufficient_phase_e_data_prqs_proxy_only")
        self.assertEqual(
            out["production_readiness_status"],
            "blocked_missing_future_matched_ab_engagement_rows",
        )
        self.assertEqual(out["observed"]["valid_matched_pair_count"], 4)
        self.assertEqual(out["observed"]["valid_matched_ab_row_count"], 8)
        self.assertEqual(out["observed"]["observed_engagement_count"], 1)
        self.assertIn("phase_e_requires_4_future_matched_engagements", out["blockers"])

    def test_phase_e_missing_evidence_artifacts_cannot_make_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows: list[dict] = []
            for idx in range(4):
                pair = f"pair-{idx}"
                rows.append(self._phase_e_row(
                    pair_id=pair,
                    engagement_id=f"eng-{idx}",
                    cohort="A",
                    metrics={"ppe": 1.0, "frph": 0.5, "prqs": 80, "supporting": 0.5},
                    evidence_paths=[str(root / "missing" / f"{pair}-A.json")],
                ))
                rows.append(self._phase_e_row(
                    pair_id=pair,
                    engagement_id=f"eng-{idx}",
                    cohort="B",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 60, "supporting": 0.4},
                    evidence_paths=[str(root / "missing" / f"{pair}-B.json")],
                ))
            out = self.tool.phase_e_measurement(
                rows_path=write_jsonl(root / "phase_e_rows.jsonl", rows),
                prqs_path=self._prqs(root),
            )
        invalid_errors = [error for row in out["observed"]["invalid_rows"] for error in row["errors"]]
        self.assertEqual(out["verdict"], "insufficient_phase_e_data_prqs_proxy_only")
        self.assertEqual(
            out["production_readiness_status"],
            "blocked_missing_future_matched_ab_engagement_rows",
        )
        self.assertEqual(out["observed"]["valid_matched_pair_count"], 0)
        self.assertEqual(out["observed"]["valid_matched_ab_row_count"], 0)
        self.assertEqual(invalid_errors.count("missing_evidence_path"), 8)
        self.assertIn("invalid_phase_e_rows_present", out["blockers"])

    def test_phase_e_rejects_non_finite_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows = [
                self._phase_e_row(
                    pair_id="pair-nan",
                    engagement_id="eng-nan",
                    cohort="A",
                    metrics={"ppe": float("nan"), "frph": 0.5, "prqs": 50, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(root, pair_id="pair-nan", engagement_id="eng-nan", cohort="A")
                    ],
                ),
                self._phase_e_row(
                    pair_id="pair-nan",
                    engagement_id="eng-nan",
                    cohort="B",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 50, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(root, pair_id="pair-nan", engagement_id="eng-nan", cohort="B")
                    ],
                ),
            ]
            out = self.tool.phase_e_measurement(
                rows_path=write_jsonl(root / "phase_e_rows.jsonl", rows),
                prqs_path=self._prqs(root),
            )
        invalid_errors = [error for row in out["observed"]["invalid_rows"] for error in row["errors"]]
        self.assertIn("invalid_metric_ppe", invalid_errors)
        self.assertEqual(out["observed"]["valid_matched_pair_count"], 0)
        self.assertIn("invalid_phase_e_rows_present", out["blockers"])

    def test_phase_e_rejects_template_rows_and_reports_pair_shape_errors(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows = [
                self._phase_e_row(
                    pair_id="pair-template",
                    engagement_id="eng-template",
                    cohort="A",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 50, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(
                            root,
                            pair_id="pair-template",
                            engagement_id="eng-template",
                            cohort="A",
                        )
                    ],
                    template_only=True,
                ),
                self._phase_e_row(
                    pair_id="pair-historical",
                    engagement_id="eng-historical",
                    cohort="A",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 50, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(
                            root,
                            pair_id="pair-historical",
                            engagement_id="eng-historical",
                            cohort="A",
                        )
                    ],
                    outcome_observed_at_utc="2026-05-23T23:59:59Z",
                ),
                self._phase_e_row(
                    pair_id="pair-unmatched",
                    engagement_id="eng-unmatched",
                    cohort="A",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 50, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(
                            root,
                            pair_id="pair-unmatched",
                            engagement_id="eng-unmatched",
                            cohort="A",
                        )
                    ],
                ),
                self._phase_e_row(
                    pair_id="pair-duplicate",
                    engagement_id="eng-duplicate",
                    cohort="A",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 50, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(
                            root,
                            pair_id="pair-duplicate",
                            engagement_id="eng-duplicate",
                            cohort="A",
                        )
                    ],
                ),
                self._phase_e_row(
                    pair_id="pair-duplicate",
                    engagement_id="eng-duplicate",
                    cohort="A",
                    metrics={"ppe": 0.4, "frph": 0.4, "prqs": 40, "supporting": 0.4},
                    evidence_paths=[
                        self._evidence(
                            root,
                            pair_id="pair-duplicate-2",
                            engagement_id="eng-duplicate",
                            cohort="A",
                        )
                    ],
                ),
                self._phase_e_row(
                    pair_id="pair-mismatch",
                    engagement_id="eng-a",
                    cohort="A",
                    metrics={"ppe": 0.5, "frph": 0.5, "prqs": 50, "supporting": 0.5},
                    evidence_paths=[
                        self._evidence(root, pair_id="pair-mismatch", engagement_id="eng-a", cohort="A")
                    ],
                ),
                self._phase_e_row(
                    pair_id="pair-mismatch",
                    engagement_id="eng-b",
                    cohort="B",
                    metrics={"ppe": 0.4, "frph": 0.4, "prqs": 40, "supporting": 0.4},
                    evidence_paths=[
                        self._evidence(root, pair_id="pair-mismatch", engagement_id="eng-b", cohort="B")
                    ],
                ),
            ]
            out = self.tool.phase_e_measurement(
                rows_path=write_jsonl(root / "phase_e_rows.jsonl", rows),
                prqs_path=self._prqs(root),
            )
        invalid_errors = [error for row in out["observed"]["invalid_rows"] for error in row["errors"]]
        self.assertEqual(out["verdict"], "insufficient_phase_e_data_prqs_proxy_only")
        self.assertIn("template_row_not_measurement", invalid_errors)
        self.assertIn("historical_outcome_not_phase_e", invalid_errors)
        self.assertIn("duplicate_pair_cohort", invalid_errors)
        self.assertIn("invalid_phase_e_rows_present", out["blockers"])
        self.assertIn("unmatched_phase_e_pairs_present", out["blockers"])
        self.assertIn("mismatched_phase_e_engagement_pairs_present", out["blockers"])


if __name__ == "__main__":
    unittest.main()
