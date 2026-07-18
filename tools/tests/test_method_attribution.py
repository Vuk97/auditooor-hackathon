"""Tests for method-attribution.py (Lane K K9)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "method-attribution.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("method_attribution", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["method_attribution"] = module
    spec.loader.exec_module(module)
    return module


# A mixed engagement: commit_mining proved/filed, detector_scan only killed,
# provider_fanout produced one accepted finding at high proof cost.
RECORDS = [
    {
        "candidate_id": "c1",
        "discovery_method": "commit_mining",
        "source_surface": "git_history",
        "time_spent_minutes": 40,
        "proof_time_minutes": 90,
        "filed_outcome": "filed",
        "moved_success_metric": True,
    },
    {
        "candidate_id": "c2",
        "discovery_method": "commit_mining",
        "source_surface": "git_history",
        "time_spent_minutes": 30,
        "proof_time_minutes": 60,
        "filed_outcome": "accepted",
        "moved_success_metric": True,
    },
    {
        "candidate_id": "c3",
        "discovery_method": "detector_scan",
        "source_surface": "go_source",
        "time_spent_minutes": 20,
        "filed_outcome": "killed",
        "killed_reason": "no_impact",
    },
    {
        "candidate_id": "c4",
        "discovery_method": "detector_scan",
        "source_surface": "go_source",
        "time_spent_minutes": 25,
        "filed_outcome": "dropped",
        "killed_reason": "oos",
    },
    {
        "candidate_id": "c5",
        "discovery_method": "provider_fanout",
        "source_surface": "provider_output",
        "time_spent_minutes": 15,
        "proof_time_minutes": 300,
        "filed_outcome": "accepted",
        "moved_success_metric": True,
    },
]


class MethodAttributionTests(unittest.TestCase):
    def test_per_method_attribution_summary(self) -> None:
        tool = load_tool()
        summary = tool.build_summary(RECORDS, engagement="dydx-iterN")
        self.assertEqual(summary["schema"], "auditooor.method_attribution.v1")
        self.assertEqual(summary["record_count"], 5)
        self.assertEqual(summary["method_count"], 3)
        by_method = {m["method"]: m for m in summary["per_method"]}
        self.assertEqual(by_method["commit_mining"]["positive_count"], 2)
        self.assertEqual(by_method["commit_mining"]["negative_count"], 0)
        self.assertEqual(by_method["detector_scan"]["positive_count"], 0)
        self.assertEqual(by_method["detector_scan"]["negative_count"], 2)
        # commit_mining has the best score (cheap, all positive).
        self.assertGreater(
            by_method["commit_mining"]["method_score"],
            by_method["detector_scan"]["method_score"],
        )
        # detector_scan produced only killed/dropped -> score 0.
        self.assertEqual(by_method["detector_scan"]["method_score"], 0.0)

    def test_budget_reweights_toward_proven_methods(self) -> None:
        tool = load_tool()
        summary = tool.build_summary(RECORDS, engagement="e1")
        budget = summary["next_dispatch_budget"]
        # Shares sum to ~1.
        self.assertAlmostEqual(sum(budget.values()), 1.0, places=2)
        # The proven method gets more budget than the dead scanner.
        self.assertGreater(budget["commit_mining"], budget["detector_scan"])
        # Dead scanner is throttled, not eliminated (exploration floor).
        self.assertGreaterEqual(budget["detector_scan"], 0.0)
        self.assertIn("commit_mining", summary["top_methods"])
        self.assertIn("detector_scan", summary["dead_methods"])
        self.assertIn("Reweight", summary["dispatch_guidance"])

    def test_budget_shift_against_prior(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            prior_path = Path(tmp) / "prior.json"
            prior_path.write_text(
                json.dumps(
                    {
                        "next_dispatch_budget": {
                            "commit_mining": 0.2,
                            "detector_scan": 0.5,
                            "provider_fanout": 0.3,
                        }
                    }
                ),
                encoding="utf-8",
            )
            summary = tool.build_summary(RECORDS, engagement="e2", prior_budget_path=prior_path)
        shift = summary["budget_shift"]
        # commit_mining should gain budget vs the prior plan, detector_scan lose.
        self.assertGreater(shift["commit_mining"], 0.0)
        self.assertLess(shift["detector_scan"], 0.0)

    def test_loads_jsonl_and_object_with_candidates(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            jsonl = Path(tmp) / "records.jsonl"
            jsonl.write_text(
                "\n".join(json.dumps(r) for r in RECORDS) + "\n", encoding="utf-8"
            )
            obj = Path(tmp) / "records.json"
            obj.write_text(json.dumps({"candidates": RECORDS}), encoding="utf-8")
            self.assertEqual(len(tool._load_records(jsonl)), 5)
            self.assertEqual(len(tool._load_records(obj)), 5)


    def test_k9_fields_captured_per_record(self) -> None:
        """K9: per-record attribution must capture discovery_method, source_surface, time, outcome."""
        tool = load_tool()
        records = [
            {
                "candidate_id": "r1",
                "discovery_method": "manual_review",
                "source_surface": "go_source",
                "agent": "claude",
                "provider": "anthropic",
                "time_spent_minutes": 45,
                "proof_time_minutes": 120,
                "filed_outcome": "filed",
                "moved_success_metric": True,
            },
            {
                "candidate_id": "r2",
                "discovery_method": "manual_review",
                "source_surface": "rust_source",
                "agent": "claude",
                "provider": "anthropic",
                "time_spent_minutes": 30,
                "proof_time_minutes": 0,
                "filed_outcome": "killed",
                "killed_reason": "no_impact",
            },
        ]
        summary = tool.build_summary(records, engagement="test_k9")
        self.assertEqual(summary["schema"], "auditooor.method_attribution.v1")
        self.assertEqual(summary["record_count"], 2)
        by_method = {m["method"]: m for m in summary["per_method"]}
        mr = by_method["manual_review"]
        # K9: discovery time and proof time summed correctly.
        self.assertAlmostEqual(mr["time_spent_minutes"], 75.0, places=1)
        self.assertAlmostEqual(mr["proof_time_minutes"], 120.0, places=1)
        # K9: positive vs negative counts correct.
        self.assertEqual(mr["positive_count"], 1)
        self.assertEqual(mr["negative_count"], 1)
        # K9: killed_reasons tracked.
        self.assertIn("no_impact", mr["killed_reasons"])
        self.assertEqual(mr["killed_reasons"]["no_impact"], 1)
        # K9: source_surfaces tracked.
        self.assertIn("go_source", mr["source_surfaces"])
        self.assertIn("rust_source", mr["source_surfaces"])

    def test_all_negative_method_scores_zero(self) -> None:
        """K9: a method with only killed/dropped outcomes should score 0.0."""
        tool = load_tool()
        all_negative = [
            {
                "candidate_id": f"n{i}",
                "discovery_method": "detector_scan",
                "source_surface": "solidity_source",
                "time_spent_minutes": 10,
                "filed_outcome": "killed",
                "killed_reason": "oos",
            }
            for i in range(5)
        ]
        summary = tool.build_summary(all_negative, engagement="neg_test")
        by_method = {m["method"]: m for m in summary["per_method"]}
        self.assertEqual(by_method["detector_scan"]["positive_count"], 0)
        self.assertEqual(by_method["detector_scan"]["negative_count"], 5)
        self.assertEqual(by_method["detector_scan"]["method_score"], 0.0)
        self.assertIn("detector_scan", summary["dead_methods"])

    def test_filed_outcome_counts_as_positive(self) -> None:
        """K9: filed and accepted outcomes both count as positive for budget reweight."""
        tool = load_tool()
        records = [
            {"candidate_id": "f1", "discovery_method": "commit_mining", "filed_outcome": "filed"},
            {"candidate_id": "f2", "discovery_method": "commit_mining", "filed_outcome": "accepted"},
            {"candidate_id": "f3", "discovery_method": "commit_mining", "filed_outcome": "escalated"},
            {"candidate_id": "f4", "discovery_method": "commit_mining", "filed_outcome": "paste_ready"},
        ]
        summary = tool.build_summary(records, engagement="pos_test")
        by_method = {m["method"]: m for m in summary["per_method"]}
        self.assertEqual(by_method["commit_mining"]["positive_count"], 4)
        self.assertEqual(by_method["commit_mining"]["negative_count"], 0)
        self.assertGreater(by_method["commit_mining"]["method_score"], 0.0)

    def test_budget_floor_prevents_method_elimination(self) -> None:
        """K9: even dead methods retain a small exploration floor in the budget."""
        tool = load_tool()
        # commit_mining proves everything; detector_scan kills everything.
        records = [
            {"candidate_id": "g1", "discovery_method": "commit_mining", "filed_outcome": "filed"},
            {"candidate_id": "g2", "discovery_method": "commit_mining", "filed_outcome": "accepted"},
            {"candidate_id": "g3", "discovery_method": "detector_scan", "filed_outcome": "killed"},
            {"candidate_id": "g4", "discovery_method": "detector_scan", "filed_outcome": "dropped"},
        ]
        summary = tool.build_summary(records, engagement="floor_test")
        budget = summary["next_dispatch_budget"]
        # Dead method must not be entirely eliminated (exploration floor).
        self.assertGreater(budget["detector_scan"], 0.0, "K9: dead method must retain exploration floor > 0")
        # Proven method should dominate.
        self.assertGreater(budget["commit_mining"], budget["detector_scan"])
        # Budget shares must sum to ~1.
        self.assertAlmostEqual(sum(budget.values()), 1.0, places=2)


if __name__ == "__main__":
    unittest.main()
