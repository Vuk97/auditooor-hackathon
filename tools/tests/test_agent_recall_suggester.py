"""Tests for tools/agent-recall-suggester.py — T1-PRIORITY-3 v0."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "agent-recall-suggester.py"


def _import():
    spec = importlib.util.spec_from_file_location(
        "agent_recall_suggester_test", str(TOOL)
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AgentRecallSuggesterTests(unittest.TestCase):
    """≥4 tests covering: empty input, single-lane regression, multi-lane mixed,
    schema validation."""

    # ---- 1. empty input -------------------------------------------------
    def test_empty_scoreboard_emits_honest_empty_doc(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            scoreboard_path = root / "missing_scoreboard.json"
            ledger_path = root / "missing_ledger.jsonl"

            payload = mod.build_suggestions(
                None,  # missing scoreboard
                [],
                scoreboard_path=scoreboard_path,
                ledger_path=ledger_path,
                regression_threshold_pp=10.0,
                top_n=25,
            )
            self.assertEqual(payload["schema"], "auditooor.agent_recall_suggester.v1")
            self.assertTrue(payload["empty_input"])
            self.assertEqual(payload["suggestions"], [])
            self.assertEqual(payload["summary"]["total_lanes"], 0)
            self.assertEqual(payload["summary"]["regressing_lanes"], 0)
            self.assertEqual(payload["summary"]["by_action"], {})

    # ---- 2. single-lane regression -------------------------------------
    def test_single_lane_regression_classifies_lower_threshold(self) -> None:
        mod = _import()
        scoreboard = {
            "schema": "auditooor.outcome_scoreboard.v1",
            "generated_at": "2026-05-07T00:00:00Z",
            "detectors": [
                {
                    "lane": "rust-decode-bomb",
                    "tp": 18,
                    "fp": 4,
                    "fn": 0,
                    "precision": 0.82,
                    "sample_size": 22,
                    "preliminary": False,
                    "rolling": {
                        "window_days": 7,
                        "tp": 9,
                        "fp": 0,
                        "fn": 0,
                        "precision": 0.95,
                    },
                },
            ],
        }
        payload = mod.build_suggestions(
            scoreboard,
            [],  # ledger has no fp_reason fields available
            scoreboard_path=Path("reports/outcome_scoreboard.json"),
            ledger_path=Path("reference/outcomes.jsonl"),
            regression_threshold_pp=10.0,
            top_n=25,
        )
        self.assertFalse(payload["empty_input"])
        self.assertEqual(payload["summary"]["total_lanes"], 1)
        self.assertEqual(payload["summary"]["regressing_lanes"], 1)
        sug = payload["suggestions"][0]
        self.assertEqual(sug["lane"], "rust-decode-bomb")
        # 0.82 - 0.95 = -0.13 -> -13 pp delta, exceeds 10pp threshold
        self.assertAlmostEqual(sug["delta_pp"], -13.0, places=4)
        # high precision but regressing -> lower-confidence-threshold
        self.assertEqual(sug["suggested_action"], "lower-confidence-threshold")
        # 22 sample size is >=10 but <30 -> medium confidence
        self.assertEqual(sug["confidence"], "medium")
        self.assertEqual(payload["summary"]["by_action"], {"lower-confidence-threshold": 1})

    # ---- 3. multi-lane mixed -------------------------------------------
    def test_multi_lane_mixed_classification(self) -> None:
        mod = _import()
        scoreboard = {
            "schema": "auditooor.outcome_scoreboard.v1",
            "generated_at": "2026-05-07T00:00:00Z",
            "detectors": [
                # Healthy + stable -> observe
                {
                    "lane": "healthy-lane",
                    "tp": 30, "fp": 1, "fn": 0,
                    "precision": 0.97, "sample_size": 31,
                    "preliminary": False,
                    "rolling": {"window_days": 7, "tp": 15, "fp": 0,
                                "fn": 0, "precision": 0.97},
                },
                # Mid band -> add-allow-list
                {
                    "lane": "mid-precision-lane",
                    "tp": 12, "fp": 8, "fn": 0,
                    "precision": 0.60, "sample_size": 20,
                    "preliminary": False,
                    "rolling": {"window_days": 7, "tp": 6, "fp": 4,
                                "fn": 0, "precision": 0.60},
                },
                # Low -> split-detector
                {
                    "lane": "low-precision-lane",
                    "tp": 4, "fp": 8, "fn": 0,
                    "precision": 0.33, "sample_size": 12,
                    "preliminary": False,
                    "rolling": None,
                },
                # Severe low -> pause
                {
                    "lane": "broken-lane",
                    "tp": 1, "fp": 11, "fn": 0,
                    "precision": 0.083, "sample_size": 12,
                    "preliminary": False,
                    "rolling": None,
                },
                # Preliminary (under threshold) -> observe + skipped counter
                {
                    "lane": "small-lane",
                    "tp": 1, "fp": 0, "fn": 0,
                    "precision": 1.0, "sample_size": 1,
                    "preliminary": True,
                    "rolling": None,
                },
            ],
        }
        # Ledger with one rejection_reason — exercises hint fallback path.
        ledger = [
            {
                "lane": "mid-precision-lane",
                "outcome": "rejected",
                "rejection_reason": "out of scope per audit rubric",
            },
            {
                "lane": "mid-precision-lane",
                "outcome": "rejected",
                "rejection_reason": "out of scope per audit rubric",
            },
        ]
        payload = mod.build_suggestions(
            scoreboard,
            ledger,
            scoreboard_path=Path("reports/outcome_scoreboard.json"),
            ledger_path=Path("reference/outcomes.jsonl"),
            regression_threshold_pp=10.0,
            top_n=25,
        )
        actions = {s["lane"]: s["suggested_action"] for s in payload["suggestions"]}
        self.assertEqual(actions["healthy-lane"], "observe")
        self.assertEqual(actions["mid-precision-lane"], "add-allow-list")
        self.assertEqual(actions["low-precision-lane"], "split-detector")
        self.assertEqual(actions["broken-lane"], "pause")
        self.assertEqual(actions["small-lane"], "observe")  # preliminary path

        self.assertEqual(payload["summary"]["preliminary_lanes_skipped"], 1)
        self.assertEqual(payload["summary"]["total_lanes"], 5)

        # Hint source resolved to rejection_reason because ledger had no fp_reason
        # but did carry rejection_reason for FP-shaped rows.
        mid = next(s for s in payload["suggestions"] if s["lane"] == "mid-precision-lane")
        self.assertEqual(mid["hint_source"], "rejection_reason")
        self.assertEqual(mid["top_fp_reason"], "out of scope per audit rubric")
        self.assertEqual(mid["top_fp_reason_count"], 2)

    # ---- 4. schema validation ------------------------------------------
    def test_schema_keys_and_types(self) -> None:
        mod = _import()
        scoreboard = {
            "schema": "auditooor.outcome_scoreboard.v1",
            "generated_at": "2026-05-07T00:00:00Z",
            "detectors": [
                {
                    "lane": "any-lane",
                    "tp": 6, "fp": 2, "fn": 0,
                    "precision": 0.75, "sample_size": 8,
                    "preliminary": False,
                    "rolling": None,
                },
            ],
        }
        payload = mod.build_suggestions(
            scoreboard,
            [],
            scoreboard_path=Path("reports/outcome_scoreboard.json"),
            ledger_path=Path("reference/outcomes.jsonl"),
            regression_threshold_pp=10.0,
            top_n=25,
        )
        # Top-level keys
        for key in (
            "schema",
            "generated_at",
            "scoreboard_path",
            "scoreboard_generated_at",
            "ledger_path",
            "ledger_row_count",
            "preliminary_threshold",
            "regression_threshold_pp",
            "empty_input",
            "suggestions",
            "summary",
        ):
            self.assertIn(key, payload, f"missing top-level key: {key}")
        self.assertEqual(payload["schema"], "auditooor.agent_recall_suggester.v1")

        # Per-suggestion keys
        sug = payload["suggestions"][0]
        for key in (
            "lane",
            "tp", "fp", "fn",
            "current_precision", "previous_precision", "delta_pp",
            "sample_size", "preliminary",
            "hint_source", "top_fp_reason", "top_fp_reason_count",
            "suggested_action", "confidence", "rationale",
        ):
            self.assertIn(key, sug, f"missing per-suggestion key: {key}")
        self.assertIn(
            sug["suggested_action"],
            {"lower-confidence-threshold", "add-allow-list",
             "split-detector", "pause", "observe"},
        )
        self.assertIn(sug["confidence"], {"low", "medium", "high"})
        self.assertIn(sug["hint_source"], {"fp_reason", "rejection_reason", "absent"})

        # JSON-serializable round-trip (catches NaN / set leakage etc.)
        round_trip = json.loads(json.dumps(payload))
        self.assertEqual(round_trip["schema"], payload["schema"])

    # ---- 5b. broadened FP-shaped outcome vocabulary --------------------
    # Loop-13 schema bridge: backfill emits fp_reason on rejected,
    # withdrawn, duplicate, and duplicate_of_rejected rows. The suggester
    # must aggregate hints across all of those to surface non-trivial
    # signal from the backfilled ledger (closes AAA L12 PARTIAL).
    def test_fp_reasons_from_broadened_outcome_vocab(self) -> None:
        mod = _import()
        scoreboard = {
            "schema": "auditooor.outcome_scoreboard.v1",
            "generated_at": "2026-05-07T00:00:00Z",
            "detectors": [
                {
                    "lane": "source-mine",
                    "tp": 5, "fp": 5, "fn": 0,
                    "precision": 0.50, "sample_size": 10,
                    "preliminary": False,
                    "rolling": None,
                },
            ],
        }
        ledger = [
            {"lane": "source-mine", "outcome": "rejected",
             "fp_reason": "unrealistic_bounds"},
            {"lane": "source-mine", "outcome": "withdrawn",
             "fp_reason": "operator_killed_pre_submit"},
            {"lane": "source-mine", "outcome": "withdrawn",
             "fp_reason": "operator_killed_pre_submit"},
            {"lane": "source-mine", "outcome": "withdrawn",
             "fp_reason": "operator_killed_pre_submit"},
            {"lane": "source-mine", "outcome": "duplicate",
             "fp_reason": "duplicate_of_other_submission"},
            {"lane": "source-mine", "outcome": "duplicate_of_rejected",
             "fp_reason": "duplicate_of_rejected_original"},
            # pending row -> ignored (not FP-shaped).
            {"lane": "source-mine", "outcome": "pending",
             "fp_reason": None},
        ]
        payload = mod.build_suggestions(
            scoreboard,
            ledger,
            scoreboard_path=Path("reports/outcome_scoreboard.json"),
            ledger_path=Path("reference/outcomes.jsonl"),
            regression_threshold_pp=10.0,
            top_n=25,
        )
        sug = payload["suggestions"][0]
        self.assertEqual(sug["hint_source"], "fp_reason")
        # operator_killed_pre_submit is most common (3 of 6 FP-shaped rows).
        self.assertEqual(sug["top_fp_reason"], "operator_killed_pre_submit")
        self.assertEqual(sug["top_fp_reason_count"], 3)
        # 0.50 precision -> add-allow-list band.
        self.assertEqual(sug["suggested_action"], "add-allow-list")

    # ---- 5. fp_reason preferred over rejection_reason -------------------
    def test_fp_reason_preferred_when_present(self) -> None:
        mod = _import()
        scoreboard = {
            "schema": "auditooor.outcome_scoreboard.v1",
            "generated_at": "2026-05-07T00:00:00Z",
            "detectors": [
                {
                    "lane": "lane-x",
                    "tp": 5, "fp": 5, "fn": 0,
                    "precision": 0.50, "sample_size": 10,
                    "preliminary": False,
                    "rolling": None,
                },
            ],
        }
        ledger = [
            # row carries fp_reason — should take priority.
            {"lane": "lane-x", "outcome": "rejected",
             "fp_reason": "selector matches OOS macro path",
             "rejection_reason": "out of scope"},
            {"lane": "lane-x", "outcome": "rejected",
             "fp_reason": "selector matches OOS macro path"},
            {"lane": "lane-x", "outcome": "rejected",
             "fp_reason": "double-counted nested call"},
        ]
        payload = mod.build_suggestions(
            scoreboard,
            ledger,
            scoreboard_path=Path("reports/outcome_scoreboard.json"),
            ledger_path=Path("reference/outcomes.jsonl"),
            regression_threshold_pp=10.0,
            top_n=25,
        )
        sug = payload["suggestions"][0]
        self.assertEqual(sug["hint_source"], "fp_reason")
        self.assertEqual(sug["top_fp_reason"], "selector matches OOS macro path")
        self.assertEqual(sug["top_fp_reason_count"], 2)
        # 0.5 precision -> add-allow-list band
        self.assertEqual(sug["suggested_action"], "add-allow-list")


if __name__ == "__main__":
    unittest.main()
