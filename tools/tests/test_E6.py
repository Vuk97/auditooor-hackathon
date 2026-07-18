#!/usr/bin/env python3
"""test_E6.py - disposition SOUNDNESS advisory axis (E6).

Extends tools/disposition-rationale-check.py with an advisory-first, NO-AUTO-
CREDIT (verdict="needs-fuzz") sub-check: a NEGATIVE disposition killed on a
GUARD or PRECONDITION basis must cite a file:line at the guard/consumer site;
a bare "unreachable in practice" is unfalsifiable and gets flagged.

Non-vacuity: the file:line predicate is load-bearing - swapping _FILE_LINE_RE
to match-always silences the mutant fixture (test_predicate_is_load_bearing).
DEDUP boundary (A1): E6 only examines entries #146 already deems 'ok', so a
mutant that E6 fires on STILL passes #146 (test_distinct_from_146). FP-guard
drops a dedup/prior-art kill whose id-proof is validly non-code.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "disposition-rationale-check.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "E6"


def _load():
    spec = importlib.util.spec_from_file_location("disp_e6", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["disp_e6"] = m
    spec.loader.exec_module(m)
    return m


class TestDispositionSoundness(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        for v in ("AUDITOOOR_DISPOSITION_SOUNDNESS_STRICT", "AUDITOOOR_L37_STRICT"):
            os.environ.pop(v, None)

    def _ws(self, fixture, md_extra="body\n"):
        d = Path(tempfile.mkdtemp())
        entry = d / "submissions" / "_oos_rejected" / "disc-projected"
        entry.mkdir(parents=True)
        (entry / "finding.md").write_text("# finding\n" + md_extra, encoding="utf-8")
        (entry / "_OOS_REJECTION.json").write_text(
            (_FIX / fixture).read_text(), encoding="utf-8")
        return d

    # ---- mutation-kill ---------------------------------------------------
    def test_mutant_precond_fires(self):
        r = self.m.soundness_check(self._ws("mutant_precond.json"))
        self.assertEqual(r["unsound_count"], 1)
        row = r["rows"][0]
        self.assertEqual(row["signal"], "precondition-dismissal")
        self.assertEqual(row["verdict"], "needs-fuzz")  # NO-AUTO-CREDIT
        self.assertEqual(r["verdict"], "warn-disposition-unsound")

    def test_mutant_guard_fires(self):
        r = self.m.soundness_check(self._ws("mutant_guard.json"))
        self.assertEqual(r["unsound_count"], 1)
        self.assertEqual(r["rows"][0]["signal"], "guard-kill")

    def test_benign_clean(self):
        # benign proof carries DiscreteAccounting.sol:462-473 -> sound.
        r = self.m.soundness_check(self._ws("benign_precond.json"))
        self.assertEqual(r["unsound_count"], 0)
        self.assertEqual(r["verdict"], "pass-disposition-soundness")

    # ---- non-vacuity: the file:line predicate is load-bearing ------------
    def test_predicate_is_load_bearing(self):
        ws = self._ws("mutant_precond.json")
        saved = self.m._FILE_LINE_RE
        try:
            # make "has a file:line" always true -> the mutant must go silent.
            self.m._FILE_LINE_RE = re.compile(r"")
            self.assertEqual(self.m.soundness_check(ws)["unsound_count"], 0,
                             "match-always file:line predicate must silence the mutant")
        finally:
            self.m._FILE_LINE_RE = saved
        self.assertEqual(self.m.soundness_check(ws)["unsound_count"], 1)

    def test_signal_predicate_is_load_bearing(self):
        ws = self._ws("mutant_precond.json")
        saved = self.m._PRECOND_TOKENS
        try:
            self.m._PRECOND_TOKENS = ("zzz_never_matches",)
            self.assertEqual(self.m.soundness_check(ws)["unsound_count"], 0,
                             "no guard/precondition signal -> out of E6 scope")
        finally:
            self.m._PRECOND_TOKENS = saved

    # ---- FP-guard --------------------------------------------------------
    def test_fp_guard_drops_dedup_basis(self):
        # duplicate/prior-audit kill: id-proof is valid, no code cite demanded.
        r = self.m.soundness_check(self._ws("dedup_basis.json"))
        self.assertEqual(r["unsound_count"], 0, "dedup-basis kill must not be flagged")

    def test_rebuttal_clears(self):
        ws = self._ws("mutant_precond.json",
                      md_extra="disposition-soundness-rebuttal: accepted by operator\n")
        self.assertEqual(self.m.soundness_check(ws)["unsound_count"], 0)

    # ---- dedup vs the existing detector (#146) ---------------------------
    def test_distinct_from_146(self):
        # E6 fires on the mutant, but #146 (field-non-empty) still PASSES it,
        # proving E6 is net-new coverage, not a re-derivation of #146.
        ws = self._ws("mutant_precond.json")
        r6 = self.m.soundness_check(ws)
        self.assertEqual(r6["unsound_count"], 1)
        self.assertFalse(r6["rows"][0]["covered_by_146"])
        r146 = self.m.check(ws)
        self.assertEqual(r146["verdict"], "pass-disposition-rationale")

    def test_dedup_skips_146_flagged(self):
        # If #146 already flags the entry (empty proof), E6 must NOT double-report.
        d = Path(tempfile.mkdtemp())
        entry = d / "submissions" / "_oos_rejected" / "x"
        entry.mkdir(parents=True)
        (entry / "f.md").write_text("# f\n", encoding="utf-8")
        (entry / "_OOS_REJECTION.json").write_text(
            json.dumps({"verdict": "INVALID (unreachable)", "rule": "requires owner",
                        "proof": ""}), encoding="utf-8")
        self.assertEqual(self.m.check(d)["verdict"], "warn-disposition-missing-rationale")
        self.assertEqual(self.m.soundness_check(d)["unsound_count"], 0,
                         "entry #146 flags is out of E6 scope (dedup boundary)")

    # ---- advisory-first gating + STRICT ----------------------------------
    def test_advisory_off_by_default(self):
        r = self.m.soundness_check(self._ws("mutant_precond.json"))
        self.assertEqual(r["verdict"], "warn-disposition-unsound")
        self.assertFalse(r["strict"])

    def test_strict_hard_fails(self):
        os.environ["AUDITOOOR_DISPOSITION_SOUNDNESS_STRICT"] = "1"
        try:
            r = self.m.soundness_check(self._ws("mutant_precond.json"))
            self.assertEqual(r["verdict"], "fail-disposition-unsound")
            self.assertTrue(r["strict"])
        finally:
            os.environ.pop("AUDITOOOR_DISPOSITION_SOUNDNESS_STRICT", None)

    def test_cli_emit_writes_jsonl(self):
        ws = self._ws("mutant_precond.json")
        out = Path(tempfile.mkdtemp()) / "disposition_soundness.jsonl"
        subprocess.run([sys.executable, str(_TOOL), "--workspace", str(ws),
                        "--soundness", "--emit", str(out)], check=True,
                       capture_output=True, text=True)
        lines = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["verdict"], "needs-fuzz")


if __name__ == "__main__":
    unittest.main()
