#!/usr/bin/env python3
"""Tests for tools/outcome-scoreboard.py — T1-P0-4 v0.

Stdlib-only, hermetic via ``tempfile.TemporaryDirectory``. Each test
scaffolds its own ledger so the live ``reference/outcomes.jsonl`` is never
touched.

Coverage:
  1. ``test_schema_valid``     — empty ledger emits the documented v1 schema
                                 with ``empty_input=true`` and never crashes.
  2. ``test_empty_input``      — missing ledger file is handled gracefully:
                                 zero rows, zero engagements, zero detectors,
                                 zero dispatchers, zero regressions.
  3. ``test_sample_correctness`` — handcrafted ledger with known TP/FP/dupe
                                  rows produces the exact precision and
                                  bucket counts (M14-trap discipline:
                                  ``preliminary`` flag set when n<5).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "outcome-scoreboard.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "outcome_scoreboard_mod", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["outcome_scoreboard_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_ledger(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


class TestOutcomeScoreboardSchema(unittest.TestCase):
    def test_schema_valid(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "outcomes.jsonl"
            out = tdp / "scoreboard.json"
            _write_ledger(ledger, [])
            rc = mod.main(
                [
                    "--outcomes",
                    str(ledger),
                    "--out",
                    str(out),
                    "--top-regressions",
                    "5",
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            # Documented v1 schema fields all present.
            for key in (
                "schema",
                "generated_at",
                "ledger_path",
                "ledger_row_count",
                "empty_input",
                "summary",
                "engagements",
                "detectors",
                "dispatchers",
                "top_regressions",
                "preliminary_threshold",
            ):
                self.assertIn(key, payload, f"missing key {key}")
            self.assertEqual(payload["schema"], "auditooor.outcome_scoreboard.v1")
            self.assertTrue(payload["empty_input"])
            self.assertEqual(payload["ledger_row_count"], 0)
            self.assertEqual(payload["preliminary_threshold"], 5)


class TestOutcomeScoreboardEmptyInput(unittest.TestCase):
    def test_empty_input(self) -> None:
        """Missing ledger == empty-but-valid scoreboard, no crash."""
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "does-not-exist.jsonl"
            out = tdp / "scoreboard.json"
            self.assertFalse(ledger.exists())
            rc = mod.main(
                ["--outcomes", str(ledger), "--out", str(out)]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertTrue(payload["empty_input"])
            self.assertEqual(payload["engagements"], [])
            self.assertEqual(payload["detectors"], [])
            self.assertEqual(payload["dispatchers"], [])
            self.assertEqual(payload["top_regressions"], [])
            self.assertEqual(payload["summary"]["by_outcome"], {})


class TestOutcomeScoreboardSampleCorrectness(unittest.TestCase):
    def test_sample_correctness(self) -> None:
        """Handcrafted ledger -> exact TP/FP/precision math."""
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "outcomes.jsonl"
            out = tdp / "scoreboard.json"
            # detector lane "alpha": 3 accepted, 1 rejected -> precision 0.75,
            #                       sample_size=4, preliminary=True (n<5).
            # detector lane "beta":  6 rejected, 0 accepted -> precision 0.0,
            #                       sample_size=6, preliminary=False.
            # dispatcher route "claude": 3 accepted (TP), 0 non-TP -> 1.0
            # dispatcher route "kimi":   0 accepted, 6 rejected -> 0.0
            rows: list[dict] = []
            for i in range(3):
                rows.append(
                    {
                        "finding_id": f"ALPHA-TP-{i}",
                        "outcome": "accepted",
                        "lane": "alpha",
                        "model_route": "claude",
                        "engagement": "engA",
                        "workspace": "wsA",
                        "severity": "Medium",
                        "resolved_at": "2026-05-01",
                    }
                )
            rows.append(
                {
                    "finding_id": "ALPHA-FP-0",
                    "outcome": "rejected",
                    "lane": "alpha",
                    "model_route": "claude",
                    "engagement": "engA",
                    "workspace": "wsA",
                    "severity": "Low",
                    "resolved_at": "2026-05-02",
                }
            )
            for i in range(6):
                rows.append(
                    {
                        "finding_id": f"BETA-FP-{i}",
                        "outcome": "rejected",
                        "lane": "beta",
                        "model_route": "kimi",
                        "engagement": "engB",
                        "workspace": "wsB",
                        "severity": "Low",
                        "resolved_at": "2026-05-03",
                    }
                )
            # one pending row to confirm pending != terminal.
            rows.append(
                {
                    "finding_id": "ALPHA-PENDING",
                    "outcome": "pending",
                    "lane": "alpha",
                    "model_route": "claude",
                    "engagement": "engA",
                    "workspace": "wsA",
                    "severity": "High",
                }
            )
            _write_ledger(ledger, rows)
            rc = mod.main(["--outcomes", str(ledger), "--out", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            self.assertEqual(payload["ledger_row_count"], len(rows))
            self.assertFalse(payload["empty_input"])
            # Outcome buckets.
            self.assertEqual(payload["summary"]["by_outcome"]["accepted"], 3)
            self.assertEqual(payload["summary"]["by_outcome"]["rejected"], 7)
            self.assertEqual(payload["summary"]["by_outcome"]["pending"], 1)
            # Detectors.
            by_lane = {d["lane"]: d for d in payload["detectors"]}
            self.assertIn("alpha", by_lane)
            self.assertIn("beta", by_lane)
            self.assertEqual(by_lane["alpha"]["tp"], 3)
            self.assertEqual(by_lane["alpha"]["fp"], 1)
            self.assertAlmostEqual(by_lane["alpha"]["precision"], 0.75)
            self.assertEqual(by_lane["alpha"]["sample_size"], 4)
            self.assertTrue(by_lane["alpha"]["preliminary"])
            self.assertEqual(by_lane["beta"]["tp"], 0)
            self.assertEqual(by_lane["beta"]["fp"], 6)
            self.assertEqual(by_lane["beta"]["precision"], 0.0)
            self.assertEqual(by_lane["beta"]["sample_size"], 6)
            self.assertFalse(by_lane["beta"]["preliminary"])
            # Dispatchers.
            by_route = {
                d["model_route"]: d for d in payload["dispatchers"]
            }
            self.assertIn("claude", by_route)
            self.assertIn("kimi", by_route)
            self.assertEqual(by_route["claude"]["tp"], 3)
            self.assertEqual(by_route["claude"]["non_tp_terminal"], 1)
            self.assertAlmostEqual(by_route["claude"]["routing_accuracy"], 0.75)
            self.assertEqual(by_route["kimi"]["tp"], 0)
            self.assertEqual(by_route["kimi"]["non_tp_terminal"], 6)
            self.assertEqual(by_route["kimi"]["routing_accuracy"], 0.0)
            # Engagements (1 row pending didn't add a new engagement key).
            engagements = {e["engagement"]: e for e in payload["engagements"]}
            self.assertIn("engA", engagements)
            self.assertEqual(engagements["engA"]["counts"]["accepted"], 3)
            self.assertEqual(engagements["engA"]["counts"]["rejected"], 1)
            self.assertEqual(engagements["engA"]["counts"]["pending"], 1)


class TestOutcomeScoreboardIsFpWidened(unittest.TestCase):
    """L14 widening: ``_is_fp`` now mirrors the suggester's
    ``_FP_SHAPED_OUTCOMES`` vocabulary (rejected, oos, duplicate, withdrawn)
    so detector-precision math surfaces the same FP-shaped lane signal the
    recall suggester aggregates. Closes Worker-JJJ L13 deferred item.
    """

    def test_is_fp_predicate_recognises_widened_buckets(self) -> None:
        mod = _load_module()
        # Widened set
        for bucket in ("rejected", "oos", "duplicate", "withdrawn"):
            self.assertTrue(
                mod._is_fp(bucket),
                f"_is_fp({bucket!r}) should be True after L14 widening",
            )
        # Still FP-negative
        for bucket in ("accepted", "pending", "other", "unknown"):
            self.assertFalse(
                mod._is_fp(bucket),
                f"_is_fp({bucket!r}) must remain False post-widening",
            )

    def test_withdrawn_and_duplicate_count_as_fp_in_detector_precision(self) -> None:
        """Detector precision math must now treat withdrawn/duplicate as FP.

        Lane "gamma" has 1 accepted + 2 withdrawn + 2 duplicate + 0 rejected.
        Pre-widening this lane would have shown precision = 1/(1+0) = 1.0.
        Post-widening: precision = 1/(1+4) = 0.2.
        """
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "outcomes.jsonl"
            out = tdp / "scoreboard.json"
            rows: list[dict] = [
                {
                    "finding_id": "GAMMA-TP-0",
                    "outcome": "accepted",
                    "lane": "gamma",
                    "model_route": "claude",
                    "engagement": "engG",
                    "workspace": "wsG",
                    "severity": "Medium",
                    "resolved_at": "2026-05-01",
                },
            ]
            for i in range(2):
                rows.append(
                    {
                        "finding_id": f"GAMMA-WD-{i}",
                        "outcome": "withdrawn",
                        "lane": "gamma",
                        "model_route": "claude",
                        "engagement": "engG",
                        "workspace": "wsG",
                        "severity": "Low",
                        "resolved_at": "2026-05-02",
                    }
                )
            for i in range(2):
                rows.append(
                    {
                        "finding_id": f"GAMMA-DUP-{i}",
                        "outcome": "duplicate",
                        "lane": "gamma",
                        "model_route": "claude",
                        "engagement": "engG",
                        "workspace": "wsG",
                        "severity": "Low",
                        "resolved_at": "2026-05-03",
                    }
                )
            _write_ledger(ledger, rows)
            rc = mod.main(["--outcomes", str(ledger), "--out", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            by_lane = {d["lane"]: d for d in payload["detectors"]}
            self.assertIn("gamma", by_lane)
            self.assertEqual(by_lane["gamma"]["tp"], 1)
            self.assertEqual(by_lane["gamma"]["fp"], 4)
            # 1 / (1+4) = 0.2 (post-widening)
            self.assertAlmostEqual(by_lane["gamma"]["precision"], 0.2)
            self.assertEqual(by_lane["gamma"]["sample_size"], 5)
            self.assertFalse(by_lane["gamma"]["preliminary"])

    def test_widening_is_invariant_for_pure_accepted_or_pure_rejected_lanes(
        self,
    ) -> None:
        """Lanes that contain only accepted+rejected outcomes must produce the
        same precision pre- and post-widening (regression guard for the
        existing ``test_sample_correctness`` cohort shape).
        """
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "outcomes.jsonl"
            out = tdp / "scoreboard.json"
            rows: list[dict] = []
            # delta: 4 accepted + 1 rejected -> precision 0.8 sample 5
            for i in range(4):
                rows.append(
                    {
                        "finding_id": f"DELTA-TP-{i}",
                        "outcome": "accepted",
                        "lane": "delta",
                        "model_route": "claude",
                        "engagement": "engD",
                        "workspace": "wsD",
                        "severity": "High",
                        "resolved_at": "2026-05-01",
                    }
                )
            rows.append(
                {
                    "finding_id": "DELTA-FP-0",
                    "outcome": "rejected",
                    "lane": "delta",
                    "model_route": "claude",
                    "engagement": "engD",
                    "workspace": "wsD",
                    "severity": "Low",
                    "resolved_at": "2026-05-02",
                }
            )
            _write_ledger(ledger, rows)
            rc = mod.main(["--outcomes", str(ledger), "--out", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            by_lane = {d["lane"]: d for d in payload["detectors"]}
            self.assertIn("delta", by_lane)
            self.assertEqual(by_lane["delta"]["tp"], 4)
            self.assertEqual(by_lane["delta"]["fp"], 1)
            self.assertAlmostEqual(by_lane["delta"]["precision"], 0.8)
            self.assertEqual(by_lane["delta"]["sample_size"], 5)


class TestOutcomeScoreboardLaneDiversityWidened(unittest.TestCase):
    """L15 lane-bucketing widening (closes Worker-JJJ L13 + Worker-NNN L14
    cumulative deferred): lanes whose rows are all pending / in_review /
    other-bucketed must STILL show up in ``detectors`` so the recall
    suggester can emit at least an ``observe`` row for them. Pre-widening
    these lanes silently disappeared.

    Discipline preserved:
      * ``sample_size`` continues to mean precision-relevant cohort
        (tp+fp+fn) so existing precision-math tests don't shift.
      * ``preliminary`` continues to gate on ``sample_size <
        PRELIMINARY_THRESHOLD`` — a lane with 22 pending rows still has
        ``sample_size=0`` and is preliminary.
      * Lane footprint is exposed via the new ``total_rows`` field so the
        operator can see lane diversity without polluting precision.
    """

    def test_pending_only_lane_still_surfaces_in_detectors(self) -> None:
        """A lane whose rows are all pending must still appear in
        ``detectors`` (precision=None, preliminary=True, total_rows>0).
        """
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "outcomes.jsonl"
            out = tdp / "scoreboard.json"
            rows: list[dict] = []
            # 5 pending rows on lane "epsilon" — pre-widening this lane
            # would have been dropped from detectors entirely.
            for i in range(5):
                rows.append(
                    {
                        "finding_id": f"EPSILON-PEND-{i}",
                        "outcome": "pending",
                        "lane": "epsilon",
                        "model_route": "claude",
                        "engagement": "engE",
                        "workspace": "wsE",
                        "severity": "Medium",
                    }
                )
            _write_ledger(ledger, rows)
            rc = mod.main(["--outcomes", str(ledger), "--out", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            by_lane = {d["lane"]: d for d in payload["detectors"]}
            self.assertIn(
                "epsilon",
                by_lane,
                "pending-only lane must still surface post-L15 widening",
            )
            ep = by_lane["epsilon"]
            self.assertEqual(ep["tp"], 0)
            self.assertEqual(ep["fp"], 0)
            self.assertEqual(ep["fn"], 0)
            self.assertEqual(ep["pending_or_other"], 5)
            self.assertEqual(ep["total_rows"], 5)
            # precision math invariants: no terminal rows -> precision None
            self.assertIsNone(ep["precision"])
            # sample_size remains precision-relevant cohort -> 0
            self.assertEqual(ep["sample_size"], 0)
            # M14-trap: 0 < threshold -> preliminary
            self.assertTrue(ep["preliminary"])

    def test_lane_diversity_widening_preserves_existing_precision_math(
        self,
    ) -> None:
        """A mixed cohort: lane "zeta" with 6 accepted + 4 rejected + 10
        pending. precision must still be 6/(6+4)=0.6 (pending must NOT
        affect precision). sample_size=10, total_rows=20.
        """
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "outcomes.jsonl"
            out = tdp / "scoreboard.json"
            rows: list[dict] = []
            for i in range(6):
                rows.append(
                    {
                        "finding_id": f"ZETA-TP-{i}",
                        "outcome": "accepted",
                        "lane": "zeta",
                        "model_route": "claude",
                        "engagement": "engZ",
                        "workspace": "wsZ",
                        "severity": "High",
                        "resolved_at": "2026-05-01",
                    }
                )
            for i in range(4):
                rows.append(
                    {
                        "finding_id": f"ZETA-FP-{i}",
                        "outcome": "rejected",
                        "lane": "zeta",
                        "model_route": "claude",
                        "engagement": "engZ",
                        "workspace": "wsZ",
                        "severity": "Low",
                        "resolved_at": "2026-05-02",
                    }
                )
            for i in range(10):
                rows.append(
                    {
                        "finding_id": f"ZETA-PEND-{i}",
                        "outcome": "pending",
                        "lane": "zeta",
                        "model_route": "claude",
                        "engagement": "engZ",
                        "workspace": "wsZ",
                        "severity": "Medium",
                    }
                )
            _write_ledger(ledger, rows)
            rc = mod.main(["--outcomes", str(ledger), "--out", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            by_lane = {d["lane"]: d for d in payload["detectors"]}
            self.assertIn("zeta", by_lane)
            z = by_lane["zeta"]
            # Precision math: pending must NOT affect tp/fp.
            self.assertEqual(z["tp"], 6)
            self.assertEqual(z["fp"], 4)
            self.assertEqual(z["pending_or_other"], 10)
            self.assertAlmostEqual(z["precision"], 0.6)
            # sample_size: precision-relevant cohort only.
            self.assertEqual(z["sample_size"], 10)
            # total_rows: full footprint including pending.
            self.assertEqual(z["total_rows"], 20)
            # 10 >= 5 -> not preliminary
            self.assertFalse(z["preliminary"])

    def test_multi_lane_widening_with_unknown_and_other_buckets(
        self,
    ) -> None:
        """Mirrors live ledger shape: lane ``unknown`` (22 rows, no
        outcome) + lane ``stub`` (2 rows, no outcome) + lane ``mine``
        (mixed terminal + pending). All three lanes must surface; the
        small ``stub`` lane must be flagged preliminary.
        """
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ledger = tdp / "outcomes.jsonl"
            out = tdp / "scoreboard.json"
            rows: list[dict] = []
            # 22 rows on lane "unknown" with no outcome at all -> "other"
            # bucket. Pre-widening these dropped silently.
            for i in range(22):
                rows.append(
                    {
                        "finding_id": f"UNK-{i}",
                        "lane": "unknown",
                        "engagement": "engU",
                        "workspace": "wsU",
                    }
                )
            # 2 rows on lane "stub" with no outcome.
            for i in range(2):
                rows.append(
                    {
                        "finding_id": f"STUB-{i}",
                        "lane": "stub",
                        "engagement": "engS",
                        "workspace": "wsS",
                    }
                )
            # mine: 2 rejected + 6 pending -> precision 0/2 = 0.0
            for i in range(2):
                rows.append(
                    {
                        "finding_id": f"MINE-FP-{i}",
                        "outcome": "rejected",
                        "lane": "mine",
                        "engagement": "engM",
                        "workspace": "wsM",
                        "resolved_at": "2026-05-04",
                    }
                )
            for i in range(6):
                rows.append(
                    {
                        "finding_id": f"MINE-PEND-{i}",
                        "outcome": "pending",
                        "lane": "mine",
                        "engagement": "engM",
                        "workspace": "wsM",
                    }
                )
            _write_ledger(ledger, rows)
            rc = mod.main(["--outcomes", str(ledger), "--out", str(out)])
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text())
            by_lane = {d["lane"]: d for d in payload["detectors"]}
            # All three lanes must surface (this is the L15 widening).
            self.assertIn("unknown", by_lane)
            self.assertIn("stub", by_lane)
            self.assertIn("mine", by_lane)
            # unknown: 22 rows, all "other" -> sample_size=0, preliminary,
            # total_rows=22, precision=None.
            unk = by_lane["unknown"]
            self.assertEqual(unk["tp"], 0)
            self.assertEqual(unk["fp"], 0)
            self.assertEqual(unk["pending_or_other"], 22)
            self.assertEqual(unk["sample_size"], 0)
            self.assertEqual(unk["total_rows"], 22)
            self.assertIsNone(unk["precision"])
            self.assertTrue(unk["preliminary"])
            # stub: 2 rows -> sample_size=0, total_rows=2, preliminary.
            stub = by_lane["stub"]
            self.assertEqual(stub["pending_or_other"], 2)
            self.assertEqual(stub["sample_size"], 0)
            self.assertEqual(stub["total_rows"], 2)
            self.assertTrue(stub["preliminary"])
            # mine: 2 rejected -> tp=0, fp=2, precision=0.0, sample=2 (so
            # preliminary because 2<5), total_rows=8.
            mine = by_lane["mine"]
            self.assertEqual(mine["tp"], 0)
            self.assertEqual(mine["fp"], 2)
            self.assertEqual(mine["pending_or_other"], 6)
            self.assertEqual(mine["sample_size"], 2)
            self.assertEqual(mine["total_rows"], 8)
            self.assertEqual(mine["precision"], 0.0)
            self.assertTrue(mine["preliminary"])  # 2 < threshold 5


if __name__ == "__main__":
    unittest.main()
