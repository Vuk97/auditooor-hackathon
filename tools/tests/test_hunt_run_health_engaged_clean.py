"""Regression: hunt-run-health must distinguish an engaged-clean hunt (model
ran every function and explicitly declined, applies_to_target=no) from a silent
failed run (null/blank/rate-limited results). A fully-executed hunt on a clean
0-finding workspace must NOT be branded failed-run. Generic fix anchor:
monero-oxide audit-run-full STRICT failed with success_fraction=0.0021 because
1887/1891 honest "no-bug-here" verdicts were lumped with never-ran records.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "hunt-run-health-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("hrh_engaged", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


HRH = _load()


def _rec_engaged_no(i):
    # model RAN and explicitly declined to anchor -> applies_to_target=no
    return {
        "status": "ok",
        "result": json.dumps({
            "applies_to_target": "no",
            "file_line": "",
            "reasoning": "designed-as-intended / no rubric row",
        }),
    }


def _rec_success(i):
    return {
        "status": "ok",
        "result": json.dumps({
            "applies_to_target": "yes",
            "file_line": "src/foo/src/lib.rs:%d" % (10 + i),
        }),
    }


def _rec_null(i):
    # genuine silent failure: produced nothing usable
    return {"status": "ok", "result": None}


def _rec_ratelimited(i):
    return {"status": "failed", "error": "429 Too Many Requests rate limit"}


def _write_dir(ws, name, recs):
    d = ws / "audit" / "corpus_tags" / "derived" / name
    d.mkdir(parents=True, exist_ok=True)
    for i, r in enumerate(recs):
        (d / ("task_%04d.json" % i)).write_text(json.dumps(r), encoding="utf-8")
    return d


class TestEngagedClean(unittest.TestCase):
    def _report(self, recs, ws_name="clean-ws"):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_dir(ws, "haiku_harness_%s_n100" % ws_name, recs)
            derived = ws / "audit" / "corpus_tags" / "derived"
            return HRH.build_report(derived, ws_name, str(ws))

    def test_engaged_clean_is_not_failed_run(self):
        # 60 functions, model engaged every one, all honest "no" -> trustworthy
        recs = [_rec_engaged_no(i) for i in range(60)]
        rep = self._report(recs)
        self.assertEqual(rep["engaged_clean"], 60)
        self.assertEqual(rep["success"], 0)
        self.assertNotEqual(rep["verdict"], "failed-run")
        self.assertFalse(rep["needs_re_hunt"])
        self.assertIn(rep["verdict"], ("healthy-clean", "healthy"))

    def test_silent_failure_still_failed_run(self):
        # 60 functions, ALL null results (never dispatched) -> failed-run
        recs = [_rec_null(i) for i in range(60)]
        rep = self._report(recs)
        self.assertEqual(rep["engaged_clean"], 0)
        self.assertEqual(rep["verdict"], "failed-run")
        self.assertTrue(rep["needs_re_hunt"])

    def test_ratelimited_still_failed_run(self):
        recs = [_rec_ratelimited(i) for i in range(60)]
        rep = self._report(recs)
        self.assertEqual(rep["verdict"], "failed-run")
        self.assertTrue(rep["needs_re_hunt"])

    def test_real_findings_still_healthy(self):
        recs = [_rec_success(i) for i in range(60)]
        rep = self._report(recs)
        self.assertEqual(rep["success"], 60)
        self.assertEqual(rep["verdict"], "healthy")

    def test_mixed_mostly_engaged_few_findings(self):
        # 2 real findings + 58 honest no -> engaged, trustworthy, not failed
        recs = [_rec_success(i) for i in range(2)] + [_rec_engaged_no(i) for i in range(58)]
        rep = self._report(recs)
        self.assertEqual(rep["success"], 2)
        self.assertEqual(rep["engaged_clean"], 58)
        self.assertNotEqual(rep["verdict"], "failed-run")

    def test_classify_engaged_vs_empty(self):
        self.assertEqual(HRH.classify_record(_rec_engaged_no(0))[0], "engaged")
        self.assertEqual(HRH.classify_record(_rec_null(0))[0], "empty")
        # garbage non-structured result with no applies_to_target -> empty
        garbage = {"status": "ok", "result": "I think this looks fine maybe"}
        self.assertEqual(HRH.classify_record(garbage)[0], "empty")


if __name__ == "__main__":
    unittest.main()
