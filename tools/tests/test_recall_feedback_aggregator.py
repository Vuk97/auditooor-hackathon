#!/usr/bin/env python3
"""Tests for tools/audit/recall-feedback-aggregator.py (Wave-5 W5-A4).

Stdlib only. All fixtures are synthetic, written into a tempdir.

Coverage matrix:
  1. Empty inputs: valid envelope, empty weight tables.
  2. FP-ledger ingest: TP/FP/NEGATIVE tally per pattern (fp_id) key,
     and per attack_class when the row carries one.
  3. outcomes.jsonl ingest: outcome -> verdict mapping; unresolved
     outcomes (pending / in_review) carry no signal.
  4. Weight math: a class behind only TPs > NEUTRAL, only misses
     < NEUTRAL, mixed near NEUTRAL; clamped to [MIN, MAX].
  5. M14-trap: a class with no verdict history is OMITTED, not
     invented at some default.
  6. fp-ledger dedupe: newest record per hit key wins (FP -> TP flip).
  7. Idempotency: re-running yields byte-identical output + same hash.
  8. Verdict-md ingest: aggregate-verdict bold token parsed.
  9. Legacy outcomes.json: rows already seen by submission_id skipped.
 10. Malformed JSON lines / comment lines skipped without crash.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit" / "recall-feedback-aggregator.py"


def _run(args, expect_rc=0):
    proc = subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == expect_rc, (
        "rc=%d stdout=%s stderr=%s"
        % (proc.returncode, proc.stdout[-400:], proc.stderr[-400:]))
    return proc


def _mkroot(tmp):
    """Build a minimal repo-root layout under tmp."""
    root = Path(tmp)
    (root / "audit").mkdir()
    (root / "reference").mkdir()
    (root / "tools").mkdir()
    (root / "agent_outputs").mkdir()
    return root


def _aggregate(root):
    _run(["--repo-root", str(root), "--quiet"])
    return json.loads((root / "recall_weights.json").read_text())


class TestRecallFeedbackAggregator(unittest.TestCase):

    def test_01_empty_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            env = _aggregate(root)
            self.assertEqual(env["schema"], "auditooor.recall_weights.v1")
            self.assertEqual(env["attack_class_weights"], {})
            self.assertEqual(env["pattern_weights"], {})
            self.assertEqual(
                env["verdict_totals"], {"TP": 0, "FP": 0, "NEGATIVE": 0})
            self.assertIn("content_hash", env)

    def test_02_fp_ledger_pattern_and_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            rows = [
                {"fp_id": "FP-01", "workspace": "w", "file": "a.sol",
                 "line": 1, "verdict": "TP", "attack_class": "reentrancy",
                 "recorded_at": "2026-05-01T00:00:00Z"},
                {"fp_id": "FP-01", "workspace": "w", "file": "b.sol",
                 "line": 2, "verdict": "FP", "attack_class": "reentrancy",
                 "recorded_at": "2026-05-01T00:00:00Z"},
            ]
            (root / "audit" / "fp_verdict_ledger.jsonl").write_text(
                "# comment\n" + "\n".join(json.dumps(r) for r in rows) + "\n")
            env = _aggregate(root)
            self.assertIn("fp-01", env["pattern_weights"])
            self.assertEqual(env["pattern_weights"]["fp-01"]["hits"], 1)
            self.assertEqual(env["pattern_weights"]["fp-01"]["misses"], 1)
            self.assertIn("reentrancy", env["attack_class_weights"])
            self.assertEqual(
                env["attack_class_weights"]["reentrancy"]["n"], 2)
            self.assertEqual(env["verdict_totals"]["TP"], 1)
            self.assertEqual(env["verdict_totals"]["FP"], 1)

    def test_03_outcomes_jsonl_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            rows = [
                {"submission_id": "s1", "lane": "lane-x", "outcome": "rejected"},
                {"submission_id": "s2", "lane": "lane-x",
                 "outcome": "duplicate"},
                {"submission_id": "s3", "lane": "lane-y", "outcome": "pending"},
                {"submission_id": "s4", "lane": "lane-z",
                 "attack_class": "theft", "outcome": "accepted"},
            ]
            (root / "reference" / "outcomes.jsonl").write_text(
                "\n".join(json.dumps(r) for r in rows) + "\n")
            env = _aggregate(root)
            acw = env["attack_class_weights"]
            # lane-x: 2 NEGATIVE -> misses, no hits.
            self.assertEqual(acw["lane-x"]["misses"], 2)
            self.assertEqual(acw["lane-x"]["hits"], 0)
            # lane-y pending -> no signal -> omitted.
            self.assertNotIn("lane-y", acw)
            # attack_class field beats lane field.
            self.assertIn("theft", acw)
            self.assertEqual(acw["theft"]["hits"], 1)

    def test_04_weight_math_direction_and_clamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            rows = []
            # all-TP class.
            for i in range(8):
                rows.append({"fp_id": "FP-WIN", "workspace": "w",
                             "file": f"{i}.sol", "line": i, "verdict": "TP",
                             "recorded_at": "2026-05-01T00:00:00Z"})
            # all-miss class.
            for i in range(8):
                rows.append({"fp_id": "FP-LOSE", "workspace": "w",
                             "file": f"L{i}.sol", "line": i, "verdict": "FP",
                             "recorded_at": "2026-05-01T00:00:00Z"})
            (root / "audit" / "fp_verdict_ledger.jsonl").write_text(
                "\n".join(json.dumps(r) for r in rows) + "\n")
            env = _aggregate(root)
            pw = env["pattern_weights"]
            self.assertGreater(pw["fp-win"]["weight"], 1.0)
            self.assertLessEqual(pw["fp-win"]["weight"], 1.5)
            self.assertLess(pw["fp-lose"]["weight"], 1.0)
            self.assertGreaterEqual(pw["fp-lose"]["weight"], 0.5)

    def test_05_m14_trap_no_history_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            # one row only; an unrelated class must NOT appear.
            (root / "audit" / "fp_verdict_ledger.jsonl").write_text(
                json.dumps({"fp_id": "FP-01", "workspace": "w",
                            "file": "a.sol", "line": 1, "verdict": "TP",
                            "recorded_at": "2026-05-01T00:00:00Z"}) + "\n")
            env = _aggregate(root)
            self.assertEqual(list(env["pattern_weights"].keys()), ["fp-01"])
            # no neutral default invented for absent classes.
            self.assertEqual(env["attack_class_weights"], {})

    def test_06_fp_ledger_dedupe_newest_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            rows = [
                {"fp_id": "FP-01", "workspace": "w", "file": "a.sol",
                 "line": 1, "verdict": "FP",
                 "recorded_at": "2026-05-01T00:00:00Z"},
                # same hit key, newer, re-triaged FP -> TP.
                {"fp_id": "FP-01", "workspace": "w", "file": "a.sol",
                 "line": 1, "verdict": "TP",
                 "recorded_at": "2026-05-09T00:00:00Z"},
            ]
            (root / "audit" / "fp_verdict_ledger.jsonl").write_text(
                "\n".join(json.dumps(r) for r in rows) + "\n")
            env = _aggregate(root)
            self.assertEqual(env["pattern_weights"]["fp-01"]["n"], 1)
            self.assertEqual(env["pattern_weights"]["fp-01"]["hits"], 1)

    def test_07_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            (root / "audit" / "fp_verdict_ledger.jsonl").write_text(
                json.dumps({"fp_id": "FP-01", "workspace": "w",
                            "file": "a.sol", "line": 1, "verdict": "TP",
                            "recorded_at": "2026-05-01T00:00:00Z"}) + "\n")
            first = (root / "recall_weights.json")
            _run(["--repo-root", str(root), "--quiet"])
            a = first.read_text()
            ha = json.loads(a)["content_hash"]
            _run(["--repo-root", str(root), "--quiet"])
            b = first.read_text()
            self.assertEqual(a, b)
            self.assertEqual(ha, json.loads(b)["content_hash"])

    def test_08_verdict_md_ingest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            d = root / "agent_outputs" / "iter_1"
            d.mkdir()
            (d / "HUNT-A1-verdict.md").write_text(
                "# HUNT-A1 verdict\n\n**Lane:** `HUNT-A1`\n\n"
                "## Aggregate verdict\n\n"
                "**NEGATIVE** - nothing fileable surfaced.\n")
            (d / "HUNT-B2-verdict.md").write_text(
                "# HUNT-B2 verdict\n\n**Lane:** HUNT-B2\n\n"
                "## Aggregate verdict\n\n"
                "**KEY FINDING** - confirmed exploit.\n")
            env = _aggregate(root)
            acw = env["attack_class_weights"]
            self.assertEqual(acw["hunt-a1"]["misses"], 1)
            self.assertEqual(acw["hunt-b2"]["hits"], 1)

    def test_09_legacy_outcomes_json_dedupe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            # s1 appears in BOTH ledgers; must count once.
            (root / "reference" / "outcomes.jsonl").write_text(
                json.dumps({"submission_id": "s1", "lane": "lane-x",
                            "outcome": "accepted"}) + "\n")
            (root / "tools" / "outcomes.json").write_text(json.dumps([
                {"submission_id": "s1", "lane": "lane-x",
                 "outcome_class": "rejected"},
                {"submission_id": "s9", "lane": "lane-q",
                 "outcome_class": "accepted"},
            ]))
            env = _aggregate(root)
            acw = env["attack_class_weights"]
            # s1 counted from jsonl only -> 1 hit, 0 miss.
            self.assertEqual(acw["lane-x"]["hits"], 1)
            self.assertEqual(acw["lane-x"]["n"], 1)
            # s9 from legacy json.
            self.assertEqual(acw["lane-q"]["hits"], 1)

    def test_10_malformed_lines_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _mkroot(tmp)
            (root / "audit" / "fp_verdict_ledger.jsonl").write_text(
                "# header comment\n"
                "{not json}\n"
                "\n"
                + json.dumps({"fp_id": "FP-01", "workspace": "w",
                              "file": "a.sol", "line": 1, "verdict": "TP",
                              "recorded_at": "2026-05-01T00:00:00Z}"}) + "\n"
                + json.dumps({"fp_id": "FP-01", "workspace": "w",
                              "file": "a.sol", "line": 1, "verdict": "TP",
                              "recorded_at": "2026-05-01T00:00:00Z"}) + "\n")
            env = _aggregate(root)
            self.assertIn("fp-01", env["pattern_weights"])


if __name__ == "__main__":
    unittest.main()
