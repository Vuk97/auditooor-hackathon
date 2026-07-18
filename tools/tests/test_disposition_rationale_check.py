#!/usr/bin/env python3
"""Regression: every _killed/ and _oos_rejected/ disposed finding must carry a
machine-recorded rationale (verdict+rule+proof). Strata 2026-07-07: three findings
(srt-haircut, ERC20Cooldown, DiscreteAccounting) were disposed; only one had a
citable WHY on disk, so "why wasn't this filed?" could not be answered from
artifacts. This gate makes the rationale mandatory (advisory-first)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("drc", _H.parent / "disposition-rationale-check.py")
_m = importlib.util.module_from_spec(_s)
sys.modules["drc"] = _m
_s.loader.exec_module(_m)


class T(unittest.TestCase):
    def _ws(self, dispo, entry, md=True, rationale=None, rationale_name=None):
        ws = Path(tempfile.mkdtemp())
        d = ws / "submissions" / dispo / entry
        d.mkdir(parents=True)
        if md:
            (d / f"{entry}.md").write_text("# finding\nstatus: killed\n")
        if rationale is not None:
            (d / (rationale_name or ("_KILL_RATIONALE.json" if dispo == "_killed"
                                     else "_OOS_REJECTION.json"))).write_text(json.dumps(rationale))
        return ws

    _GOOD = {"verdict": "DROPPED (dupe)", "rule": "R47 dedup",
             "proof": "matches disclosed H-1 at Foo.sol:36-38"}

    def test_complete_rationale_passes(self):
        ws = self._ws("_killed", "f1", rationale=self._GOOD)
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-rationale")

    def test_missing_rationale_warns_by_default(self):
        ws = self._ws("_killed", "f1", rationale=None)
        r = _m.check(ws)
        self.assertEqual(r["verdict"], "warn-disposition-missing-rationale")
        self.assertEqual(r["noncompliant_count"], 1)

    def test_missing_rationale_hard_fails_under_strict(self):
        ws = self._ws("_oos_rejected", "f1", rationale=None)
        os.environ["AUDITOOOR_DISPOSITION_RATIONALE_STRICT"] = "1"
        try:
            self.assertEqual(_m.check(ws)["verdict"], "fail-disposition-missing-rationale")
        finally:
            del os.environ["AUDITOOOR_DISPOSITION_RATIONALE_STRICT"]

    def test_incomplete_rationale_flagged(self):
        # missing `proof` -> incomplete, noncompliant
        ws = self._ws("_killed", "f1", rationale={"verdict": "x", "rule": "y"})
        r = _m.check(ws)
        self.assertEqual(r["noncompliant_count"], 1)
        self.assertEqual([i for i in r["items"] if i["entry"] == "f1"][0]["status"],
                         "incomplete-rationale")

    def test_rebuttal_clears_entry(self):
        ws = self._ws("_killed", "f1", md=False)
        (ws / "submissions" / "_killed" / "f1" / "f1.md").write_text(
            "# finding\n<!-- disposition-rationale-rebuttal: legacy pre-gate kill, operator-acked -->\n")
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-rationale")

    def test_bare_dir_no_md_ignored(self):
        # a dir with no finding .md (bare artifacts) is not a disposed finding
        ws = self._ws("_killed", "f1", md=False)
        self.assertEqual(_m.check(ws)["disposed_count"], 0)

    def test_oos_rejection_name_recognized(self):
        ws = self._ws("_oos_rejected", "f1", rationale=self._GOOD,
                      rationale_name="_OOS_REJECTION.json")
        self.assertEqual(_m.check(ws)["verdict"], "pass-disposition-rationale")


if __name__ == "__main__":
    unittest.main()
