# r36-rebuttal: lane hacker-reweighting-fix registered in .auditooor/agent_pathspec.json
"""Guard tests for the hacker-reweighting worklist finalizer in
tools/auto-coverage-closer.py (_reweight_dedup_sort_worklist + helpers).

Component: hacker-reweighting. The per_fn_hacker_questions worklist used to be
a flat glob-order append with NO per-row score, NO dedup, and a generic
access-control skew. These tests pin the fix:

  1. the repo-level recall-gap scoreboard is parsed into {class -> score};
  2. a question is scored via the recall-gap priority of its coarse class;
  3. the assembled worklist is de-duplicated by (unit, normalized question);
  4. the worklist is STABLE score-sorted (highest recall-gap first), so a
     P0 fund-loss / recipient class outranks the generic access-control bulk;
  5. a MISSING scoreboard degrades gracefully (dedup-only, no crash).
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent


def _load(name: str, rel: str):
    path = TOOLS_DIR / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


ACC = _load("acc_reweight_under_test", "auto-coverage-closer.py")


def _write_scoreboard(repo_root: Path, priorities: list[dict]) -> None:
    rep = repo_root / "reports"
    rep.mkdir(parents=True, exist_ok=True)
    (rep / "realworld_recall_gap_priorities.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.realworld_recall_gap_priorities.v1",
                "priorities": priorities,
            }
        ),
        encoding="utf-8",
    )


def _write_worklist(ws: Path, rows: list[dict]) -> Path:
    out = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _read_worklist(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


class TestRecallGapLoader(unittest.TestCase):
    def test_loads_class_priority_from_scoreboard(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_scoreboard(
                root,
                [
                    {"attack_class": "fund-loss-via-arithmetic", "priority_score": 71.8},
                    {"attack_class": "admin-bypass", "priority_score": 59.5},
                ],
            )
            cp = ACC._load_recall_gap_class_priority(root)
            self.assertEqual(cp["fund-loss-via-arithmetic"], 71.8)
            self.assertEqual(cp["admin-bypass"], 59.5)

    def test_missing_scoreboard_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(ACC._load_recall_gap_class_priority(Path(td)), {})

    def test_malformed_scoreboard_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            (root / "reports" / "realworld_recall_gap_priorities.json").write_text(
                "not json", encoding="utf-8"
            )
            self.assertEqual(ACC._load_recall_gap_class_priority(root), {})


class TestQuestionScoring(unittest.TestCase):
    CP = {
        "fund-loss-via-arithmetic": 71.8,
        "missing-recipient-validation": 66.6,
        "admin-bypass": 59.5,
    }

    def test_access_control_maps_to_admin_bypass(self):
        q = "Does fn require the correct onlyOwner admin role / access check?"
        self.assertEqual(ACC._score_question(q, self.CP), 59.5)

    def test_fund_loss_outranks_access_control(self):
        fund_q = "Construct an attack where the deposit/withdraw conservation invariant is violated and funds are lost."
        access_q = "Does fn enforce the admin role / access permission?"
        self.assertGreater(
            ACC._score_question(fund_q, self.CP),
            ACC._score_question(access_q, self.CP),
        )

    def test_unknown_class_falls_back_to_default(self):
        q = "Some unrelated question with no recall-gap keyword at all."
        self.assertEqual(
            ACC._score_question(q, self.CP), ACC._RECALL_GAP_DEFAULT_SCORE
        )

    def test_empty_priority_map_is_flat_default(self):
        q = "Does fn enforce the admin role / access permission?"
        self.assertEqual(ACC._score_question(q, {}), ACC._RECALL_GAP_DEFAULT_SCORE)


class TestWorklistFinalizer(unittest.TestCase):
    def test_dedup_score_sort(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            _write_scoreboard(
                root,
                [
                    {"attack_class": "fund-loss-via-arithmetic", "priority_score": 71.8},
                    {"attack_class": "admin-bypass", "priority_score": 59.5},
                ],
            )
            # 4 access-control rows (the historical bulk) + 1 fund-loss row,
            # with a duplicate access-control row to prove dedup.
            rows = [
                {"unit_id": "A::f1", "question": "Does f1 enforce the admin role access check?"},
                {"unit_id": "A::f1", "question": "Does f1 enforce the admin role access check?"},  # dup
                {"unit_id": "A::f2", "question": "Does f2 enforce the owner permission?"},
                {"unit_id": "A::f3", "question": "Does f3 enforce authorized access?"},
                {"unit_id": "B::g1", "question": "Construct an attack where the withdraw conservation invariant is violated and funds drain."},
            ]
            out = _write_worklist(ws, rows)
            res = ACC._reweight_dedup_sort_worklist(ws, repo_root=root)

            self.assertTrue(res["reweighted"])
            self.assertTrue(res["recall_gap_signal"])
            self.assertEqual(res["dropped_dups"], 1)

            final = _read_worklist(out)
            # dedup: 5 input rows -> 4 unique
            self.assertEqual(len(final), 4)
            # every row carries a per-row score
            self.assertTrue(all("priority_score" in r for r in final))
            # score-sorted descending: the fund-loss row (71.8) is FIRST,
            # ahead of the access-control bulk (59.5).
            self.assertEqual(final[0]["unit_id"], "B::g1")
            self.assertGreater(final[0]["priority_score"], final[1]["priority_score"])
            scores = [r["priority_score"] for r in final]
            self.assertEqual(scores, sorted(scores, reverse=True))

    def test_graceful_without_scoreboard(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)  # no reports/ scoreboard
            ws = root / "ws"
            ws.mkdir()
            rows = [
                {"unit_id": "A::f1", "question": "q one"},
                {"unit_id": "A::f1", "question": "q one"},  # dup
                {"unit_id": "A::f2", "question": "q two"},
            ]
            out = _write_worklist(ws, rows)
            res = ACC._reweight_dedup_sort_worklist(ws, repo_root=root)
            self.assertTrue(res["reweighted"])
            self.assertFalse(res["recall_gap_signal"])
            self.assertEqual(res["dropped_dups"], 1)
            final = _read_worklist(out)
            self.assertEqual(len(final), 2)
            # flat default score, still stable order
            self.assertTrue(all(r["priority_score"] == ACC._RECALL_GAP_DEFAULT_SCORE for r in final))
            self.assertEqual([r["unit_id"] for r in final], ["A::f1", "A::f2"])

    def test_no_worklist_is_noop(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            res = ACC._reweight_dedup_sort_worklist(ws, repo_root=Path(td))
            self.assertFalse(res["reweighted"])
            self.assertEqual(res["reason"], "no_worklist")

    def test_r80_no_claim_fields_added(self):
        """The finalizer attaches ONLY priority_score - never an attack_class,
        severity, or finding label (R80 finding-evidence-honesty)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            _write_scoreboard(root, [{"attack_class": "admin-bypass", "priority_score": 59.5}])
            out = _write_worklist(ws, [{"unit_id": "A::f1", "question": "Does f1 enforce admin access?"}])
            ACC._reweight_dedup_sort_worklist(ws, repo_root=root)
            row = _read_worklist(out)[0]
            for banned in ("attack_class", "severity", "likely_severity", "impact", "finding", "bug_class"):
                self.assertNotIn(banned, row)
            self.assertIn("priority_score", row)


if __name__ == "__main__":
    unittest.main()
