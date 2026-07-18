# <!-- r36-rebuttal: lane FIX-BODY-PACK-PERFN registered via agent-pathspec-register.py -->
"""Guard: --per-function UNIVERSAL mode builds a per-function task for ALL languages
(sol/go/rust) from the scope-correct function_coverage_completeness.json, each with the REAL
body embedded inline (closes the Go/Rust file-level gap of the inscope_units path)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_hunt_batch_builder"] = m
    spec.loader.exec_module(m)
    return m


class PerFunctionUniversalTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)
        # one real source file per language
        (self.ws / "a.sol").write_text("contract A {\n  function f() public { uint x = 1; }\n}\n", encoding="utf-8")
        (self.ws / "b.go").write_text("package b\nfunc G() int {\n  return 1\n}\n", encoding="utf-8")
        (self.ws / "c.rs").write_text("impl C {\n  pub fn h(&self) -> u64 {\n    1\n  }\n}\n", encoding="utf-8")
        cov = {"functions": [
            {"name": "f", "file": "a.sol", "line": 2, "lang": "sol", "classification": "untouched"},
            {"name": "G", "file": "b.go", "line": 2, "lang": "go", "classification": "hollow"},
            {"name": "h", "file": "c.rs", "line": 2, "lang": "rs", "classification": "real-attack"},
        ]}
        (self.ws / ".auditooor" / "function_coverage_completeness.json").write_text(json.dumps(cov), encoding="utf-8")

    def test_all_languages_per_function_body_embedded(self):
        tasks, err = self.m.build_tasks_per_function(self.ws, None, False, None, False, embed_source=True)
        self.assertIsNone(err, err)
        by = {t["lang"]: t for t in tasks}
        self.assertEqual(set(by), {"sol", "go", "rs"})            # all 3 languages got a task
        for lang in ("sol", "go", "rs"):
            self.assertTrue(by[lang]["body_embedded"], f"{lang} body not embedded")
            self.assertIn("TARGET FUNCTION", by[lang]["prompt"])
        self.assertIn("uint x = 1;", by["sol"]["prompt"])          # real body inline
        self.assertIn("return 1", by["go"]["prompt"])

    def test_only_uncovered_keeps_untouched_and_hollow_drops_real_attack(self):
        tasks, _ = self.m.build_tasks_per_function(self.ws, None, True, None, False, embed_source=True)
        langs = {t["lang"] for t in tasks}
        self.assertIn("sol", langs)   # untouched kept
        self.assertIn("go", langs)    # hollow kept
        self.assertNotIn("rs", langs)  # real-attack dropped by only_uncovered

    def test_missing_coverage_list_errors_cleanly(self):
        (self.ws / ".auditooor" / "function_coverage_completeness.json").unlink()
        tasks, err = self.m.build_tasks_per_function(self.ws, None, False, None, False)
        self.assertIsNone(tasks)
        self.assertIn("no per-function list", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
