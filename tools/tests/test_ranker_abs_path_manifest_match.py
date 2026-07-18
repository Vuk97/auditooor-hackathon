"""Loop-fix 2026-06-23 (etherfi step-3): filter_to_fork_scoped_manifest dropped EVERY
per-fn question when the questions carried an ABSOLUTE source_path (<ws>/src/...) while
the inscope_units manifest stored WS-RELATIVE rows ('/src/...'). _scope._norm leaves an
absolute path absolute, so the membership test `_norm(f) not in inscope` was always true
-> 200/200 dropped -> `make hunt-scoped` built 0 tasks -> step-3 could not dispatch. The
fix makes the membership check path-form-agnostic (also tests the ws-relative reduction of
the question file). An absolute-path question whose ws-relative form IS a manifest row must
be KEPT; a genuinely out-of-manifest file must still be dropped.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("rk_abs", str(_TOOLS / "per-fn-question-ranker.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rk_abs"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestRankerAbsPathManifestMatch(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        if self.m._scope is None:
            self.skipTest("scope lib unavailable")
        self.ws = Path(tempfile.mkdtemp()).resolve()
        (self.ws / ".auditooor").mkdir(parents=True)
        (self.ws / "src" / "cash").mkdir(parents=True)
        (self.ws / "src" / "cash" / "Foo.sol").write_text("contract Foo{}")
        # manifest stores WS-RELATIVE rows (leading-slash form, as the emitter writes)
        with (self.ws / ".auditooor" / "inscope_units.jsonl").open("w") as fh:
            fh.write(json.dumps({"file": "src/cash/Foo.sol", "function": "bar"}) + "\n")

    def _q(self, abspath, fn="bar"):
        return {"unit_id": f"{abspath}::{fn}", "source_path": abspath,
                "question": "conservation?", "priority_score": 50.0}

    def test_absolute_path_question_kept_when_in_manifest(self):
        absf = str(self.ws / "src" / "cash" / "Foo.sol")
        kept, dropped = self.m.filter_to_fork_scoped_manifest([self._q(absf)], self.ws)
        self.assertEqual(len(kept), 1, "absolute-path question whose ws-relative form is in the manifest must be KEPT")
        self.assertEqual(dropped, 0)

    def test_genuinely_oos_file_still_dropped(self):
        absf = str(self.ws / "src" / "cash" / "NotInManifest.sol")
        (self.ws / "src" / "cash" / "NotInManifest.sol").write_text("contract X{}")
        kept, dropped = self.m.filter_to_fork_scoped_manifest([self._q(absf)], self.ws)
        self.assertEqual(len(kept), 0, "a file genuinely absent from the manifest must still be dropped")
        self.assertEqual(dropped, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
