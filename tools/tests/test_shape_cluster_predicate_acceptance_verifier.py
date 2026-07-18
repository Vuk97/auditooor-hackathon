#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "shape-cluster-predicate-acceptance-verifier.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("shape_cluster_acceptance_verifier", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


class ShapeClusterPredicateAcceptanceVerifierTests(unittest.TestCase):
    def _summary(self, emitted: int = 2) -> dict:
        return {
            "schema": "auditooor.phase_ii17.batch_shape_cluster_predicates.v1.summary",
            "annotation": {
                "annotation_method": "batch-join-existing-jsonl-index-no-record-mining",
                "annotation_rows": 20,
            },
            "constraints": {
                "network": False,
                "provider_calls": False,
                "per_record_mining": False,
                "cluster_key_excludes_attack_class": True,
            },
            "clusters": {
                "cluster_count": 4,
                "target_coverage_reached": True,
                "selected_annotation_coverage": 0.8,
                "selected_predicate_count": emitted,
                "emitted_candidate_rows": emitted,
                "full_validation_pass_count": 1,
                "out_of_cluster_zero_fp_pass_count": emitted,
            },
        }

    def _report(self, semantic: int, shape: int = 0, rows: int = 30) -> dict:
        return {
            "summary_card": {
                "composability": {
                    "p1_match_tier_counts": {
                        "SEMANTIC-MATCH": semantic,
                        "TOPICAL-MATCH": max(0, rows - semantic),
                    },
                    "shape_cluster_predicate_semantic_matches": shape,
                }
            },
            "entry_points": [{} for _ in range(rows)],
        }

    def test_passes_distillation_and_reports_exact_target_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "summary.json"
            predicates = root / "predicate_candidates.jsonl"
            hyperbridge = root / "hyperbridge.json"
            morpho = root / "morpho.json"
            _write_json(summary, self._summary())
            _write_jsonl(
                predicates,
                [
                    {"candidate_status": "validated-shape-cluster-pending-dogfood"},
                    {"candidate_status": "rejected-shape-validation"},
                ],
            )
            _write_json(hyperbridge, self._report(semantic=3, shape=0))
            _write_json(morpho, self._report(semantic=7, shape=10))

            payload = TOOL.build_payload(
                summary_json=summary,
                predicates_jsonl=predicates,
                targets=[
                    ("hyperbridge", 3, hyperbridge),
                    ("morpho", 5, morpho),
                ],
            )

            self.assertTrue(payload["passed"])
            self.assertEqual(payload["distillation"]["live_target_eligible_candidate_rows"], 1)
            self.assertEqual(payload["targets"]["hyperbridge"]["semantic_missing"], 0)
            self.assertEqual(
                payload["targets"]["hyperbridge"]["shape_evidence_gap"],
                "no-shape-cluster-predicate-semantic-match",
            )
            self.assertEqual(payload["targets"]["morpho"]["semantic_missing"], 0)
            self.assertEqual(payload["targets"]["morpho"]["shape_evidence_gap"], "none")

    def test_fails_with_exact_missing_semantic_gap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "summary.json"
            predicates = root / "predicate_candidates.jsonl"
            report = root / "centrifuge.json"
            _write_json(summary, self._summary(emitted=1))
            _write_jsonl(predicates, [{"candidate_status": "pending-live-target-dogfood"}])
            _write_json(report, self._report(semantic=2, shape=1))

            payload = TOOL.build_payload(
                summary_json=summary,
                predicates_jsonl=predicates,
                targets=[("centrifuge", 5, report)],
            )

            self.assertFalse(payload["passed"])
            self.assertFalse(payload["targets"]["centrifuge"]["passed"])
            self.assertEqual(payload["targets"]["centrifuge"]["semantic_missing"], 3)
            self.assertEqual(payload["targets"]["centrifuge"]["shape_evidence_gap"], "none")

    def test_missing_report_is_an_acceptance_gap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "summary.json"
            predicates = root / "predicate_candidates.jsonl"
            _write_json(summary, self._summary(emitted=1))
            _write_jsonl(predicates, [{"candidate_status": "pending-live-target-dogfood"}])

            payload = TOOL.build_payload(
                summary_json=summary,
                predicates_jsonl=predicates,
                targets=[("hyperbridge", 3, root / "missing.json")],
            )

            self.assertFalse(payload["passed"])
            self.assertEqual(payload["targets"]["hyperbridge"]["status"], "missing-report")
            self.assertEqual(payload["targets"]["hyperbridge"]["semantic_missing"], 3)

    def test_rejects_distillation_when_candidate_count_drifts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = root / "summary.json"
            predicates = root / "predicate_candidates.jsonl"
            report = root / "morpho.json"
            _write_json(summary, self._summary(emitted=2))
            _write_jsonl(predicates, [{"candidate_status": "pending-live-target-dogfood"}])
            _write_json(report, self._report(semantic=5, shape=1))

            payload = TOOL.build_payload(
                summary_json=summary,
                predicates_jsonl=predicates,
                targets=[("morpho", 5, report)],
            )

            self.assertFalse(payload["passed"])
            checks = payload["distillation"]["checks"]
            self.assertFalse(checks["predicate_jsonl_count_matches_summary"])


if __name__ == "__main__":
    unittest.main()
