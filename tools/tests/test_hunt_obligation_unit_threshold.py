#!/usr/bin/env python3
# <!-- r36-rebuttal: lane HUNT-OBLIGATION-UNIT-THRESHOLD registered in commit message -->
"""hunt-obligation-resolve threshold = distinct UNIT count, not question/total_tasks.

Strata 2026-06-30: 370 ranked questions clustered into 224 distinct (file,function)
units. The per-fn hunt writes ONE verdict sidecar per UNIT, so the obligation threshold
(_expected_tasks => 370 questions) was structurally unreachable - a perfect exhaustive
hunt tops out at 224 sidecars and the gate could never go green. Pin: _expected_units
returns the distinct-unit count, and it is < the question count when questions > units.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-obligation-resolve.py"
_spec = importlib.util.spec_from_file_location("hor", _T)
hor = importlib.util.module_from_spec(_spec)
sys.modules["hor"] = hor
_spec.loader.exec_module(hor)


class UnitThresholdTest(unittest.TestCase):
    def _ws_with_ranked(self, rows):
        ws = Path(tempfile.mkdtemp(prefix="hor_"))
        (ws / ".auditooor").mkdir()
        p = ws / ".auditooor" / "per_fn_hacker_questions.jsonl.ranked.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return ws

    def test_distinct_units_below_question_count(self):
        # 5 questions over 2 distinct (file,function) units
        rows = [
            {"file": "A.sol", "function": "foo", "question": "q1"},
            {"file": "A.sol", "function": "foo", "question": "q2"},
            {"file": "A.sol", "function": "foo", "question": "q3"},
            {"file": "B.sol", "function": "bar", "question": "q4"},
            {"file": "B.sol", "function": "bar", "question": "q5"},
        ]
        ws = self._ws_with_ranked(rows)
        self.assertEqual(hor._expected_units(ws), 2)
        self.assertLess(hor._expected_units(ws), len(rows))

    def test_abs_and_rel_path_same_unit_not_double_counted(self):
        # the strata root cause: the same unit spelled absolute AND ws-relative must
        # collapse to ONE unit, not two.
        ws = Path(tempfile.mkdtemp(prefix="hor_"))
        (ws / ".auditooor").mkdir()
        rel = "src/contracts/Accounting.sol"
        rows = [
            {"file": f"{ws}/{rel}", "function": "totalAssets"},   # absolute spelling
            {"file": rel, "function": "totalAssets"},             # ws-relative spelling
            {"file": rel, "function": "srtNav"},
        ]
        p = ws / ".auditooor" / "per_fn_hacker_questions.jsonl.ranked.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        # 3 rows, but totalAssets is one unit (abs==rel) -> 2 distinct units
        self.assertEqual(hor._expected_units(ws), 2)

    def test_no_ranked_file_returns_zero(self):
        ws = Path(tempfile.mkdtemp(prefix="hor_"))
        (ws / ".auditooor").mkdir()
        self.assertEqual(hor._expected_units(ws), 0)

    def test_malformed_lines_skipped(self):
        ws = self._ws_with_ranked([{"file": "A.sol", "function": "foo"}])
        p = ws / ".auditooor" / "per_fn_hacker_questions.jsonl.ranked.jsonl"
        p.write_text('{"file":"A.sol","function":"foo"}\nNOT JSON\n\n', encoding="utf-8")
        self.assertEqual(hor._expected_units(ws), 1)


class BaseUnitKeyTest(unittest.TestCase):
    """per-impact-frames (2026-07-02): the dispatch obligation must gate on
    DISTINCT-UNIT coverage, not a frame-INFLATED raw sidecar count - else many
    frames of a few functions would green a thin hunt."""

    def test_frame_suffix_stripped_to_base_unit(self):
        a = hor._base_unit_key("hunt__Tranche.sol__withdraw__ab12__L282__I-direct-theft-funds.json")
        b = hor._base_unit_key("hunt__Tranche.sol__withdraw__ab12__L282__I-permanent-freeze-funds.json")
        self.assertEqual(a, b)
        self.assertEqual(a, "hunt__Tranche.sol__withdraw__ab12__L282")

    def test_legacy_frameless_name_maps_to_itself(self):
        # backward-compat: a legacy no-frame sidecar has no __I- suffix.
        n = "hunt__Tranche.sol__withdraw__ab12__L282"
        self.assertEqual(hor._base_unit_key(n + ".json"), n)
        self.assertEqual(hor._base_unit_key(n + ".jsonl"), n)

    def _ws_with_sidecars(self, names, ranked_units):
        ws = Path(tempfile.mkdtemp(prefix="hor_bu_"))
        scd = ws / ".auditooor" / "hunt_findings_sidecars"
        scd.mkdir(parents=True)
        for nm in names:
            (scd / nm).write_text(json.dumps(
                {"verdict": "cleared", "applies_to_target": "no",
                 "source_ref": "X.sol:1", "reasoning": "x" * 50}), encoding="utf-8")
        p = ws / ".auditooor" / "per_fn_hacker_questions.jsonl.ranked.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in ranked_units), encoding="utf-8")
        (ws / ".auditooor" / "hunt_provider_obligation.json").write_text(json.dumps(
            {"schema": "auditooor.hunt_provider_obligation.v1",
             "status": "orchestrator-dispatch-required",
             "hunt_provider": "agent-via-orchestrator"}), encoding="utf-8")
        return ws

    def test_many_frames_few_units_does_not_false_green(self):
        # 6 sidecars but only 2 distinct units (3 frames each); threshold = 3 units.
        names = [f"hunt__A.sol__foo__h1__L1__I-{f}.json"
                 for f in ("direct-theft-funds", "permanent-freeze-funds", "sum-preserved")]
        names += [f"hunt__B.sol__bar__h2__L2__I-{f}.json"
                  for f in ("direct-theft-funds", "permanent-freeze-funds", "sum-preserved")]
        ranked = [{"file": "A.sol", "function": "foo"}, {"file": "B.sol", "function": "bar"},
                  {"file": "C.sol", "function": "baz"}]  # 3 units expected
        ws = self._ws_with_sidecars(names, ranked)
        n, n_units, _ = hor._count_genuine_sidecars(ws)
        self.assertEqual(n, 6)          # raw count inflated by frames
        self.assertEqual(n_units, 2)    # only 2 distinct units actually hunted
        res = hor.resolve(ws, dry_run=True)
        self.assertEqual(res["action"], "still-required")  # 2 units < 3 threshold

    def test_min_sidecars_override_uses_raw_count(self):
        # explicit operator floor is a RAW sidecar count (per-frame cells count).
        names = [f"hunt__A.sol__foo__h1__L1__I-{f}.json"
                 for f in ("direct-theft-funds", "permanent-freeze-funds")]
        ws = self._ws_with_sidecars(names, [{"file": "A.sol", "function": "foo"}])
        res = hor.resolve(ws, dry_run=True, min_sidecars=2)
        self.assertNotEqual(res["action"], "still-required")


if __name__ == "__main__":
    unittest.main(verbosity=2)
