#!/usr/bin/env python3
"""Regression: auto-coverage-closer ADVISORY FOLDS must be resolvable.

An auto-coverage-closer advisory fold (`_seed_advisory_obligations`, needs-fuzz
hypotheses from the net-new/general-logic screens) was emitted WITHOUT the
{advisory_only, source_kind} fields the hacker-question gate's corpus-grounding
branch keys on, so it matched NEITHER the grounding credit NOR a per-question
source sidecar - a permanent OPEN row that fail-open-hacker-questions could never
resolve (axelar-dlt 2026-07-13: 9 folds stuck open, no resolving branch).

This locks in:
  (1) the fold is emitted tagged advisory_only=True + source_kind=
      auto_coverage_closer_advisory_fold, AND with a non-vacuous corpus-driven-hunt
      GROUNDED the gate credits it (open == 0);
  (2) NEVER-FALSE-PASS: a genuine (untagged) per-fn obligation is NOT advisory and
      still requires a real per-fn verdict sidecar - grounding alone does NOT
      credit it, it stays OPEN.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


class TestAdvFoldGroundingCredit(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.acc = _load("acc_advfold", "audit-completeness-check.py")
        self.closer = _load("closer_advfold", "auto-coverage-closer.py")

    def tearDown(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)
        if self._saved is not None:
            os.environ["AUDITOOOR_L37_STRICT"] = self._saved

    def _ws(self, tmp: Path) -> Path:
        (tmp / ".auditooor").mkdir(parents=True, exist_ok=True)
        src = tmp / "x" / "nexus" / "keeper"
        src.mkdir(parents=True, exist_ok=True)
        (src / "transfer.go").write_text(
            "package keeper\nfunc (k Keeper) ApplyTransfer(ctx Ctx) error "
            "{ return nil }\n", encoding="utf-8")
        return tmp

    def _ground(self, tmp: Path):
        """Stage a non-vacuous corpus-driven-hunt so grounding is present."""
        (tmp / ".auditooor" / "corpus_driven_hunt.json").write_text(
            json.dumps({"hypotheses": [
                {"class": "arith", "in_target_evidence": "x/nexus/keeper/transfer.go:2"}
            ]}), encoding="utf-8")

    def test_advisory_fold_tagged_and_grounding_credited(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = self._ws(Path(d))
            records = [{
                "question": "[GEN_4B] does ApplyTransfer round against the beneficiary?",
                "unit_id": "ApplyTransfer",
                "source_path": "x/nexus/keeper/transfer.go",
                "function_name": "ApplyTransfer",
                "language": "go",
                "attack_class": "divide-before-multiply",
            }]
            appended = self.closer._seed_advisory_obligations(tmp, records)
            self.assertGreaterEqual(appended, 1, "advisory fold must seed >=1 obligation")

            obl = tmp / ".auditooor" / "hacker_question_obligations.jsonl"
            rows = [json.loads(l) for l in obl.read_text().splitlines() if l.strip()]
            fold = [r for r in rows
                    if r.get("question_source") == "auto-coverage-closer-advisory-fold"]
            self.assertEqual(len(fold), 1)
            # (1) emitted tagged so the grounding branch recognizes it
            self.assertIs(fold[0].get("advisory_only"), True)
            self.assertEqual(fold[0].get("source_kind"),
                             "auto_coverage_closer_advisory_fold")

            self._ground(tmp)
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            res = self.acc.check_hacker_questions_resolved(tmp)
            self.assertEqual(res.detail.get("open"), 0, res.detail)
            self.assertTrue(res.ok,
                            "grounded advisory fold must be credited, not open")

    def test_grounded_advisory_fold_stays_open_without_grounding(self):
        """The fold is credited ONLY via genuine grounding: no corpus-driven-hunt =>
        the advisory fold is honestly still OPEN (grounding is not a free pass)."""
        with tempfile.TemporaryDirectory() as d:
            tmp = self._ws(Path(d))
            records = [{
                "question": "[GEN_4B] does ApplyTransfer round against the beneficiary?",
                "unit_id": "ApplyTransfer",
                "source_path": "x/nexus/keeper/transfer.go",
                "function_name": "ApplyTransfer",
                "language": "go",
                "attack_class": "divide-before-multiply",
            }]
            self.closer._seed_advisory_obligations(tmp, records)
            # NO grounding staged
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            res = self.acc.check_hacker_questions_resolved(tmp)
            self.assertEqual(res.detail.get("open"), 1, res.detail)
            self.assertFalse(res.ok)

    def test_genuine_perfn_untagged_needs_sidecar_never_grounding_credited(self):
        """NEVER-FALSE-PASS: a genuine per-fn obligation is untagged (not advisory),
        so even WITH grounding present it is NOT grounding-credited - it stays OPEN
        until a real per-fn verdict sidecar exists."""
        with tempfile.TemporaryDirectory() as d:
            tmp = self._ws(Path(d))
            genuine = {
                "obligation_id": "genuine1", "state": "open",
                "file": "x/nexus/keeper/transfer.go",
                "function_name": "ApplyTransfer",
                "question_source": "per-fn", "language": "go",
                "question": "auth-gated?",
            }
            # a genuine per-fn row must NOT carry the advisory tag
            self.assertNotIn("advisory_only", genuine)
            self.assertNotIn("source_kind", genuine)
            (tmp / ".auditooor" / "hacker_question_obligations.jsonl").write_text(
                json.dumps(genuine) + "\n", encoding="utf-8")
            self._ground(tmp)  # grounding present, but must not credit a genuine row
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            res = self.acc.check_hacker_questions_resolved(tmp)
            self.assertEqual(res.detail.get("open"), 1, res.detail)
            self.assertFalse(res.ok,
                             "genuine per-fn row must stay open without a sidecar")


if __name__ == "__main__":
    unittest.main()
