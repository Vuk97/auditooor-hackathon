#!/usr/bin/env python3
# r36: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
"""test_per_fn_hacker_questions_aggregate.py - FIX 1 regression lock.

auto-coverage-closer.run() writes per-unit verdict sidecars at
.auditooor/coverage_unit_verdicts/<slug>.json, each carrying
adversarial_questions + question_count. FIX 1 folds every sidecar with
question_count>=1 into ONE aggregate JSONL at
<ws>/.auditooor/per_fn_hacker_questions.jsonl, one record per (unit, question),
tagged schema_version="auditooor.per_fn_hacker_questions.v1". The L37
hacker-questions gate globs the .auditooor top level for
per_fn_hacker_questions* and accepts >=1 genuine JSONL line.

HONEST (R80): each record carries the question string ONLY - no attack_class,
no severity, no claim. Generic across languages: the fold reads whatever the
per-unit pass wrote.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load_acc():
    spec = importlib.util.spec_from_file_location(
        "acc_under_test", TOOLS / "auto-coverage-closer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PerFnHackerQuestionsAggregateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.acc = _load_acc()
        self.tmp = Path(tempfile.mkdtemp())
        self.ws = self.tmp / "ws"
        self.vdir = self.ws / ".auditooor" / "coverage_unit_verdicts"
        self.vdir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sidecar(self, slug: str, unit: str, source: str, questions: list[str]) -> None:
        rec = {
            "schema": self.acc.PER_UNIT_VERDICT_SCHEMA,
            "unit_id": unit,
            "source_path": source,
            "verdict": (self.acc.VERDICT_NEEDS_LLM if questions
                        else self.acc.VERDICT_NO_FINDING),
            "adversarial_questions": questions,
            "question_count": len(questions),
        }
        (self.vdir / f"{slug}.json").write_text(json.dumps(rec), encoding="utf-8")

    def test_fold_emits_one_record_per_question(self) -> None:
        self._sidecar("a", "a.rs::f", "a.rs", ["Q1?", "Q2?"])
        self._sidecar("b", "b.rs::g", "b.rs", ["Q3?"])
        # zero-question unit must be excluded
        self._sidecar("c", "c.rs::h", "c.rs", [])
        res = self.acc._fold_per_fn_hacker_questions(self.ws, "rid")
        self.assertEqual(res["records"], 3)
        self.assertEqual(res["units_with_questions"], 2)
        out = self.ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(out.is_file())
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)
        recs = [json.loads(l) for l in lines]
        for r in recs:
            self.assertEqual(r["schema_version"],
                             self.acc.PER_FN_HACKER_QUESTIONS_SCHEMA)
            self.assertIn("question", r)
            self.assertIn("unit_id", r)
            # HONESTY: no claim fields
            self.assertNotIn("attack_class", r)
            self.assertNotIn("severity", r)
            self.assertNotIn("claim", r)

    def test_path_is_l37_gate_visible(self) -> None:
        self._sidecar("a", "a.rs::f", "a.rs", ["Q1?"])
        res = self.acc._fold_per_fn_hacker_questions(self.ws, "")
        # the gate globs <ws>/.auditooor top level for per_fn_hacker_questions*
        self.assertTrue(res["path"].endswith(
            "/.auditooor/per_fn_hacker_questions.jsonl"))

    def test_empty_when_no_questions(self) -> None:
        self._sidecar("c", "c.rs::h", "c.rs", [])
        res = self.acc._fold_per_fn_hacker_questions(self.ws, "")
        self.assertEqual(res["records"], 0)
        out = self.ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
        self.assertTrue(out.is_file())
        self.assertEqual(out.read_text().strip(), "")

    def test_blank_questions_filtered(self) -> None:
        # whitespace-only / non-string questions must not produce records
        self._sidecar("a", "a.rs::f", "a.rs", ["  ", "real?"])
        res = self.acc._fold_per_fn_hacker_questions(self.ws, "")
        self.assertEqual(res["records"], 1)

    def test_l37_check_accepts_aggregate(self) -> None:
        # r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
        # Faithfully exercise the real L37 gate against the produced artifact.
        # audit-completeness-check.py defines dataclasses, so it must be loaded
        # under a STABLE module name registered in sys.modules (else dataclass
        # field resolution on py3.12+ fails when the module is GC'd).
        import sys
        self._sidecar("a", "a.rs::f", "a.rs", ["Q1?"])
        self.acc._fold_per_fn_hacker_questions(self.ws, "")
        modname = "audit_completeness_check_under_test"
        if modname in sys.modules:
            l37 = sys.modules[modname]
        else:
            spec = importlib.util.spec_from_file_location(
                modname, TOOLS / "audit-completeness-check.py")
            l37 = importlib.util.module_from_spec(spec)
            sys.modules[modname] = l37
            spec.loader.exec_module(l37)
        res = l37.check_hacker_questions(self.ws)
        self.assertTrue(res.ok, getattr(res, "reason", ""))


if __name__ == "__main__":
    unittest.main()
