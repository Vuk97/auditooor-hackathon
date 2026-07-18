#!/usr/bin/env python3
"""Focused test for hackerman-q-to-detector-promote.py.

Verifies the question -> reasoner promotion pipeline's Stage-0 gate:

  * a synthetic question class with >= min_tp answered obligations across
    engagements and NO crystallized detector emits a QUALIFYING promotion
    candidate;
  * ``killed`` obligations are NOT counted as TPs (and never as FPs);
  * a class that already has a crystallized detector is suppressed
    (already_has_detector, not qualifying) even above the TP bar;
  * ledger _history TP verdicts corroborate obligation TPs;
  * --dry-run has no side effects (writes no draft file).

Run:  python3 tools/tests/test_q_to_detector_promote.py
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hackerman-q-to-detector-promote.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("q2d_under_test", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["q2d_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_tool()


def _write_obligations(ws_dir: Path, rows: list[dict]) -> None:
    aud = ws_dir / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    p = aud / "hacker_question_obligations.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _ob(cls: str, state: str, ws: str, q: str = "does X validate Y?") -> dict:
    return {
        "schema": "auditooor.hacker_question_obligation.v1",
        "attack_class": cls,
        "state": state,
        "workspace": ws,
        "question": q,
        "function_name": "foo",
    }


class Stage0SelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        # empty ledger + empty patterns dir by default
        self.ledger = self.base / "_hits_ledger.yaml"
        self.ledger.write_text("version: 1\ndetectors: {}\n")
        self.patterns = self.base / "patterns.dsl"
        self.patterns.mkdir()
        self.audits = self.base / "audits"
        self.audits.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _select(self, **kw):
        return MOD.select_candidates(
            ledger_path=self.ledger,
            workspace_glob=str(self.audits / "*"),
            patterns_dir=self.patterns,
            **kw,
        )

    def test_synthetic_5tp_question_emits_candidate(self) -> None:
        # 5 answered rows for a novel class across 3 workspaces + 1 killed.
        wss = ["wsA", "wsA", "wsB", "wsB", "wsC"]
        for i, ws in enumerate(wss):
            wsd = self.audits / ws
            rows = [_ob("novel-donation-inflation", "answered", str(wsd),
                        "does vault read balanceOf(this) as totalAssets?")]
            if i == 0:
                rows.append(_ob("novel-donation-inflation", "killed", str(wsd)))
            # append (a ws may hold several rows)
            aud = wsd / ".auditooor"
            aud.mkdir(parents=True, exist_ok=True)
            p = aud / "hacker_question_obligations.jsonl"
            with p.open("a", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r) + "\n")

        cands = self._select(min_tp=5, min_workspaces=1)
        by = {c["class_stem"]: c for c in cands}
        self.assertIn("novel-donation-inflation", by)
        c = by["novel-donation-inflation"]
        self.assertTrue(c["qualifies"], c)
        self.assertEqual(c["tp_total"], 5)
        self.assertEqual(c["tp_obligations"], 5)
        self.assertEqual(c["killed_obligations"], 1)
        self.assertEqual(c["fp_total"], 0)  # killed is NOT an FP
        self.assertEqual(c["distinct_workspaces"], 3)
        self.assertTrue(c["representative_question"])

    def test_below_bar_does_not_qualify(self) -> None:
        for ws in ["wsA", "wsB"]:
            _write_obligations(self.audits / ws,
                               [_ob("rare-class", "answered", str(self.audits / ws))])
        cands = self._select(min_tp=5, min_workspaces=1)
        c = next(x for x in cands if x["class_stem"] == "rare-class")
        self.assertFalse(c["qualifies"])
        self.assertEqual(c["tp_total"], 2)

    def test_existing_detector_suppresses_candidate(self) -> None:
        # class already has a crystallized DSL pattern -> suppressed even >=5 TP.
        (self.patterns / "already-covered-class.yaml").write_text("pattern: x\n")
        for i in range(6):
            ws = self.audits / f"ws{i}"
            _write_obligations(ws, [_ob("already-covered-class", "answered", str(ws))])
        cands = self._select(min_tp=5, min_workspaces=1)
        c = next(x for x in cands if x["class_stem"] == "already-covered-class")
        self.assertTrue(c["already_has_detector"])
        self.assertFalse(c["qualifies"])

    def test_ledger_tp_corroborates_obligations(self) -> None:
        # 3 answered obligations + a ledger detector (different-name so it is NOT
        # in the suppression stem-set) is not how corroboration works; instead
        # test the ledger evidence aggregation directly on a matching stem.
        self.ledger.write_text(
            "version: 1\n"
            "detectors:\n"
            "  combo-class:\n"
            "    tp: 0\n    fp: 0\n"
            "    _history:\n"
            "    - {workspace: wsX, verdict: TP, date: '2026-01-01'}\n"
            "    - {workspace: wsY, verdict: TP, date: '2026-01-02'}\n"
        )
        # A matching-stem detector exists -> it would be suppressed. So to test
        # pure corroboration we use min_tp that the obligations alone miss but
        # obligation+ledger meets, and assert the evidence math (ignoring the
        # suppression flag by checking tp_total directly).
        for ws in ["wsA", "wsB", "wsC"]:
            _write_obligations(self.audits / ws,
                               [_ob("combo-class", "answered", str(self.audits / ws))])
        cands = self._select(min_tp=5, min_workspaces=1)
        c = next(x for x in cands if x["class_stem"] == "combo-class")
        self.assertEqual(c["tp_obligations"], 3)
        self.assertEqual(c["tp_ledger"], 2)
        self.assertEqual(c["tp_total"], 5)
        # distinct workspaces = union(wsA,wsB,wsC,wsX,wsY) = 5
        self.assertEqual(c["distinct_workspaces"], 5)

    def test_dry_run_has_no_side_effects(self) -> None:
        for i in range(5):
            ws = self.audits / f"ws{i}"
            _write_obligations(ws, [_ob("dryrun-class", "answered", str(ws))])
        res = MOD.run_pipeline(
            ledger_path=self.ledger,
            workspace_glob=str(self.audits / "*"),
            patterns_dir=self.patterns,
            min_tp=5,
            min_workspaces=1,
            dry_run=True,
        )
        self.assertEqual(res["pipeline_runs"], [])
        self.assertGreaterEqual(res["qualifying_count"], 1)
        # dry-run must not have written a HYPOTHESIS draft into the real repo.
        draft = ROOT / "reference" / "patterns.dsl" / "HYPOTHESIS-dryrun-class.yaml"
        self.assertFalse(draft.exists())


class KebabNormalisationTests(unittest.TestCase):
    def test_kebab_class(self) -> None:
        self.assertEqual(MOD.kebab_class("External-State Mutating Fn"),
                         "external-state-mutating-fn")
        self.assertEqual(MOD.kebab_class("  R4  "), "r4")
        self.assertEqual(MOD.kebab_class("!!!"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
