#!/usr/bin/env python3
"""PR 112 offline tests for tools/outcome_reweight.py + mining-prioritizer.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from outcome_reweight import (  # noqa: E402
    classify_angle,
    compute_reweight,
    load_outcome_history,
)


MINING_PRIORITIZER = TOOLS / "mining-prioritizer.py"


def _write_outcomes(path: Path, records: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")


class TestOutcomeReweight(unittest.TestCase):
    # ---------- case 1 ----------
    def test_empty_history_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            # missing file
            history = load_outcome_history(path)
            self.assertEqual(history, {})
            angle = {"id": "A-REENT", "title": "reentrancy foo"}
            delta, lines = compute_reweight(angle, history, "ws1")
            self.assertEqual(delta, 0.0)
            self.assertEqual(lines, [])
            # empty file
            path.write_text("")
            history = load_outcome_history(path)
            delta, lines = compute_reweight(angle, history, "ws1")
            self.assertEqual(delta, 0.0)
            self.assertEqual(lines, [])

    # ---------- case 2 ----------
    def test_accepted_class_promoted(self) -> None:
        records = [
            {"title": "reentrancy in vault withdraw", "outcome": "accepted",
             "status": "Paid", "workspace": "ws-a"},
            {"title": "reentrancy flash swap", "outcome": "accepted",
             "status": "Paid", "workspace": "ws-b"},
            {"title": "reentrancy on deposit", "outcome": "pending",
             "status": "Pending", "workspace": "ws-a"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            # 3 total, 2 accepted -> accept rate 66%, >= 30%
            angle = {"id": "A-REENT", "title": "reentrancy vault"}
            delta, lines = compute_reweight(angle, history, "ws-new")
            self.assertGreaterEqual(delta, 2.0)
            joined = "\n".join(lines)
            self.assertIn("paid", joined)
            self.assertIn("outcome_history_version=", joined)

    # ---------- case 3 ----------
    def test_dupe_heavy_class_penalized(self) -> None:
        records = [
            {"title": f"oracle manipulation #{i}", "outcome": "duplicate",
             "status": "Duplicate", "workspace": "ws-a"}
            for i in range(5)
        ] + [
            {"title": "oracle stale price", "outcome": "pending",
             "status": "Pending", "workspace": "ws-a"},
            {"title": "oracle drift", "outcome": "pending",
             "status": "Pending", "workspace": "ws-a"},
            {"title": "oracle tolerance", "outcome": "pending",
             "status": "Pending", "workspace": "ws-a"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            # total=8, duplicate=5 -> 62.5% dupe rate
            angle = {"id": "A-ORACLE", "title": "oracle foo"}
            delta, lines = compute_reweight(angle, history, "ws-new")
            self.assertLessEqual(delta, -3.0)
            joined = "\n".join(lines)
            self.assertIn("dupe rate", joined)

    # ---------- case 4 ----------
    def test_self_workspace_surfaced_class(self) -> None:
        records = [
            {"title": "access control missing role", "outcome": "pending",
             "status": "Pending", "workspace": "polymarket"},
            {"title": "access control wrong modifier", "outcome": "pending",
             "status": "Pending", "workspace": "polymarket"},
            {"title": "access control stale", "outcome": "pending",
             "status": "Pending", "workspace": "polymarket"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            angle = {"id": "A-AUTH", "title": "access control gap"}
            delta, lines = compute_reweight(angle, history, "polymarket")
            self.assertLessEqual(delta, -1.0)
            self.assertTrue(any("already surfaced" in line for line in lines))

    def test_unknown_reason_declines_do_not_feed_class_learning(self) -> None:
        records = [
            {
                "title": f"oracle manipulation #{i}",
                "outcome": "rejected",
                "status": "DECLINED by Cantina (no decline reason provided to operator)",
                "workspace": "morpho",
                "rejection_reason": "unknown:no decline reason provided by platform",
            }
            for i in range(3)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            angle = {"id": "A-ORACLE", "title": "oracle foo"}
            delta, lines = compute_reweight(angle, history, "morpho")
            self.assertEqual(delta, 0.0)
            self.assertEqual(lines, [])

    def test_blank_reason_declines_do_not_feed_rejected_reason_learning(self) -> None:
        records = [
            {
                "title": "oracle duplicate out of scope proof failure",
                "outcome_class": "rejected",
                "status": "DECLINED (no decline reason provided to operator)",
                "workspace": "centrifuge",
                "rejection_reason": "",
            },
            {
                "title": "oracle duplicate out of scope proof failure",
                "outcome_class": "rejected",
                "status": "DECLINED without reason",
                "workspace": "morpho",
                "rejection_reason": "",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            angle = {"id": "A-ORACLE", "title": "oracle proof failure"}
            delta, lines = compute_reweight(angle, history, "morpho")
            self.assertEqual(delta, 0.0)
            self.assertEqual(lines, [])
            self.assertNotIn("oracle", history)

    # ---------- case 5 ----------
    def test_compound_accepted_and_dupe_heavy(self) -> None:
        # 10 total: 3 accepted (30%), 5 duplicate (50%).
        records = []
        for i in range(3):
            records.append({"title": f"vault inflation #{i}", "outcome": "accepted",
                            "status": "Paid", "workspace": f"ws-{i}"})
        for i in range(5):
            records.append({"title": f"vault withdraw bug #{i}", "outcome": "duplicate",
                            "status": "Duplicate", "workspace": "ws-a"})
        for i in range(2):
            records.append({"title": f"vault misc #{i}", "outcome": "pending",
                            "status": "Pending", "workspace": "ws-a"})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            angle = {"id": "A-VAULT", "title": "vault inflation"}
            delta, lines = compute_reweight(angle, history, "ws-new")
            # +2.0 (accepted) -3.0 (dupe) = -1.0
            self.assertAlmostEqual(delta, -1.0, places=5)
            joined = "\n".join(lines)
            self.assertIn("paid", joined)
            self.assertIn("dupe rate", joined)

    # ---------- case 6: integration through mining-prioritizer.py ----------
    def test_mining_prioritizer_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "fake-ws"
            ws.mkdir()
            # CCIA with two angles: one class paid, one unknown.
            ccia = {
                "ccia": {},
                "attack_angles": [
                    {
                        "id": "A-REENT",
                        "severity": "MEDIUM",
                        "title": "reentrancy candidate",
                        "contracts": ["Foo"],
                    },
                    {
                        "id": "A-TIMESTAMP",
                        "severity": "MEDIUM",
                        "title": "timestamp thing",
                        "contracts": ["Bar"],
                    },
                ],
            }
            (ws / "ccia_report.json").write_text(json.dumps(ccia))

            outcomes_path = root / "outcomes.jsonl"
            _write_outcomes(
                outcomes_path,
                [
                    {"title": "reentrancy vault A", "outcome": "accepted",
                     "status": "Paid", "workspace": "other"},
                    {"title": "reentrancy vault B", "outcome": "accepted",
                     "status": "Paid", "workspace": "other"},
                    {"title": "reentrancy vault C", "outcome": "pending",
                     "status": "Pending", "workspace": "other"},
                ],
            )

            # Run WITH reweighting.
            proc = subprocess.run(
                [
                    sys.executable,
                    str(MINING_PRIORITIZER),
                    str(ws),
                    "--json",
                    "--outcomes-path",
                    str(outcomes_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            by_id = {row["id"]: row for row in data}
            self.assertIn("A-REENT", by_id)
            self.assertIn("A-TIMESTAMP", by_id)
            # Paid class must score strictly higher than the unknown class
            # (ties allowed would defeat the point — base A-REENT already
            # outscored A-TIMESTAMP, so we check the reweighted sort order
            # keeps A-REENT on top with a positive delta).
            self.assertGreater(
                by_id["A-REENT"]["reweight_delta"], 0.0,
                "paid class should get promoted",
            )
            self.assertEqual(
                by_id["A-TIMESTAMP"]["reweight_delta"], 0.0,
                "unknown class should be unchanged",
            )
            self.assertGreater(
                by_id["A-REENT"]["score"],
                by_id["A-TIMESTAMP"]["score"],
            )

    # ---------- case 7 ----------
    def test_no_outcome_reweight_flag_matches_pre_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "fake-ws"
            ws.mkdir()
            ccia = {
                "ccia": {},
                "attack_angles": [
                    {
                        "id": "A-REENT",
                        "severity": "MEDIUM",
                        "title": "reentrancy thing",
                        "contracts": ["Foo"],
                    },
                ],
            }
            (ws / "ccia_report.json").write_text(json.dumps(ccia))

            outcomes_path = root / "outcomes.jsonl"
            _write_outcomes(
                outcomes_path,
                [
                    {"title": "reentrancy paid A", "outcome": "accepted",
                     "status": "Paid", "workspace": "other"},
                    {"title": "reentrancy paid B", "outcome": "accepted",
                     "status": "Paid", "workspace": "other"},
                    {"title": "reentrancy paid C", "outcome": "accepted",
                     "status": "Paid", "workspace": "other"},
                ],
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(MINING_PRIORITIZER),
                    str(ws),
                    "--json",
                    "--no-outcome-reweight",
                    "--outcomes-path",
                    str(outcomes_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(len(data), 1)
            row = data[0]
            self.assertEqual(row["pre_reweight_score"], row["score"])
            self.assertEqual(row["reweight_delta"], 0.0)
            self.assertEqual(row["reweight_rationale"], [])

    # Codex PR-102 non-blocker 1: paid outcomes must count as accepted.
    def test_paid_outcome_counts_as_accepted(self) -> None:
        records = [
            {"title": "reentrancy vault A", "outcome": "paid",
             "status": "Paid", "workspace": "ws-a"},
            {"title": "reentrancy vault B", "outcome": "paid",
             "status": "Paid", "workspace": "ws-b"},
            {"title": "reentrancy vault C", "outcome": "pending",
             "status": "Pending", "workspace": "ws-a"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            # Before the fix: 0/3 accepted -> no promotion. After: 2/3 -> +2.0.
            stats = history.get("reentrancy")
            self.assertIsNotNone(stats)
            self.assertEqual(stats["accepted"], 2)
            angle = {"id": "A-REENT", "title": "reentrancy foo"}
            delta, lines = compute_reweight(angle, history, "ws-new")
            self.assertGreaterEqual(delta, 2.0)
            self.assertTrue(any("paid" in line.lower() for line in lines))

    def test_mixed_accepted_and_paid_both_count(self) -> None:
        records = [
            {"title": "reentrancy A", "outcome": "accepted",
             "status": "Paid", "workspace": "ws-a"},
            {"title": "reentrancy B", "outcome": "paid",
             "status": "Paid", "workspace": "ws-b"},
            {"title": "reentrancy C", "outcome": "paid",
             "status": "Paid", "workspace": "ws-c"},
            {"title": "reentrancy D", "outcome": "pending",
             "status": "Pending", "workspace": "ws-a"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            stats = history["reentrancy"]
            self.assertEqual(stats["accepted"], 3)
            self.assertEqual(stats["total"], 4)

    # Codex PR-102 non-blocker 2: self-workspace penalty must always apply,
    # even when the class history has fewer than 3 records.
    def test_self_workspace_penalty_applies_below_three_records(self) -> None:
        records = [
            {"title": "access control missing role", "outcome": "pending",
             "status": "Pending", "workspace": "polymarket"},
            {"title": "access control stale", "outcome": "pending",
             "status": "Pending", "workspace": "polymarket"},
        ]  # only 2 records — would previously early-return at (total<3)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            angle = {"id": "A-AUTH", "title": "access control gap"}
            delta, lines = compute_reweight(angle, history, "polymarket")
            self.assertAlmostEqual(delta, -1.0)
            self.assertTrue(any("already surfaced" in line for line in lines))
            # Statistical signals should still be suppressed at this sample size.
            self.assertFalse(any("paid" in line for line in lines))
            self.assertFalse(any("dupe rate" in line for line in lines))

    def test_self_workspace_penalty_applies_with_single_record(self) -> None:
        records = [
            {"title": "oracle stale price", "outcome": "pending",
             "status": "Pending", "workspace": "polymarket"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "outcomes.jsonl"
            _write_outcomes(path, records)
            history = load_outcome_history(path)
            angle = {"id": "A-ORACLE", "title": "oracle staleness"}
            delta, lines = compute_reweight(angle, history, "polymarket")
            self.assertAlmostEqual(delta, -1.0)
            self.assertTrue(any("already surfaced" in line for line in lines))

    def test_classify_angle_fallback(self) -> None:
        self.assertEqual(classify_angle({"id": "A-AUTH"}), "access-control")
        self.assertEqual(classify_angle({"id": "A-REENT"}), "reentrancy")
        # Fallback by keyword.
        self.assertEqual(
            classify_angle({"id": "CUSTOM-X", "title": "oracle stale price"}),
            "oracle",
        )
        self.assertIsNone(
            classify_angle({"id": "CUSTOM-X", "title": "totally unrelated text here"})
        )


if __name__ == "__main__":
    unittest.main()
