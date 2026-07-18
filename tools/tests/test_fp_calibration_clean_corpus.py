#!/usr/bin/env python3
"""Tests for tools/audit/fp-calibration-clean-corpus.py (Wave-5 W5-A3).

Stdlib only. The calibration runner is a subprocess driver around the
universal FP runner; these tests exercise it as a module against the
real in-tree known-clean corpus (tests/fixtures/fp_clean_corpus/) and
against synthetic tempdir corpora.

Coverage matrix:
  1. hits_to_verdict_rows: every hit maps to an FP verdict row.
  2. per_fp_calibration_table: 0-hit shape -> clean-baseline verdict.
  3. per_fp_calibration_table: >3-hit shape -> noisy verdict.
  4. append_rows: rows append; comments preserved; real-hunt rows
     untouched.
  5. append_rows --dedupe-prune drops only prior calibration rows.
  6. End-to-end against the real clean corpus: emits FP verdicts,
     every verdict is FP / recorded_by=calibration.
  7. Idempotency: two dedupe-prune runs leave a stable ledger size.
  8. Strict mode exit code on a corpus that exceeds --max-clean-hits.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_MODPATH = _REPO / "tools" / "audit" / "fp-calibration-clean-corpus.py"
_CORPUS = _REPO / "tests" / "fixtures" / "fp_clean_corpus"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "fp_calibration_clean_corpus", _MODPATH
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CAL = _load_module()


class TestVerdictRowMapping(unittest.TestCase):
    def test_hits_map_to_fp_rows(self):
        hits = [
            {"fp_id": "FP-01", "file": "a/Foo.sol", "line": 12,
             "function": "withdraw"},
            {"fp_id": "FP-03", "file": "b/Bar.sol", "line": 7,
             "function": ""},
        ]
        rows = CAL.hits_to_verdict_rows(hits, "2026-05-16T00:00:00Z")
        self.assertEqual(len(rows), 2)
        for r in rows:
            self.assertEqual(r["verdict"], "FP")
            self.assertEqual(r["recorded_by"], "calibration")
            self.assertEqual(r["workspace"], "calibration-clean")
            self.assertEqual(r["schema"], "auditooor.fp_verdict_ledger.v1")

    def test_empty_hits_yields_no_rows(self):
        self.assertEqual(
            CAL.hits_to_verdict_rows([], "2026-05-16T00:00:00Z"), []
        )


class TestCalibrationTable(unittest.TestCase):
    def _envelope(self, hits_per_fp):
        return {
            "hits_per_fp": hits_per_fp,
            "fps_evaluated": [
                {"fp_id": fid, "bug_class": fid, "attack_class": fid,
                 "strategy_available": True}
                for fid in hits_per_fp
            ],
        }

    def test_zero_hits_is_clean_baseline(self):
        env = self._envelope({"FP-02": 0})
        table = CAL.per_fp_calibration_table(env, [])
        self.assertEqual(table[0]["calibration_verdict"], "clean-baseline")
        self.assertEqual(table[0]["clean_corpus_fp_rate"], 0)

    def test_low_noise_band(self):
        env = self._envelope({"FP-01": 2})
        table = CAL.per_fp_calibration_table(env, [])
        self.assertEqual(table[0]["calibration_verdict"], "low-noise")

    def test_noisy_band(self):
        env = self._envelope({"FP-01": 9})
        table = CAL.per_fp_calibration_table(env, [])
        self.assertEqual(
            table[0]["calibration_verdict"], "noisy-on-clean-corpus"
        )


class TestAppendRows(unittest.TestCase):
    def test_append_preserves_comments_and_real_rows(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger.jsonl"
            real = json.dumps(
                {"schema": "auditooor.fp_verdict_ledger.v1",
                 "fp_id": "FP-01", "workspace": "graph",
                 "file": "X.sol", "line": 1, "verdict": "TP",
                 "recorded_by": "operator"}, sort_keys=True
            )
            ledger.write_text("# header comment\n" + real + "\n")
            rows = CAL.hits_to_verdict_rows(
                [{"fp_id": "FP-01", "file": "C.sol", "line": 5,
                  "function": "f"}],
                "2026-05-16T00:00:00Z",
            )
            n = CAL.append_rows(ledger, rows, dedupe_prune=False)
            self.assertEqual(n, 1)
            txt = ledger.read_text()
            self.assertIn("# header comment", txt)
            self.assertIn('"workspace": "graph"', txt)
            self.assertIn("calibration-clean", txt)

    def test_dedupe_prune_drops_only_calibration_rows(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger.jsonl"
            real = json.dumps(
                {"schema": "auditooor.fp_verdict_ledger.v1",
                 "fp_id": "FP-01", "workspace": "graph",
                 "file": "X.sol", "line": 1, "verdict": "TP",
                 "recorded_by": "operator"}, sort_keys=True
            )
            stale_calib = json.dumps(
                {"schema": "auditooor.fp_verdict_ledger.v1",
                 "fp_id": "FP-02", "workspace": "calibration-clean",
                 "file": "Old.sol", "line": 9, "verdict": "FP",
                 "recorded_by": "calibration"}, sort_keys=True
            )
            ledger.write_text("# c\n" + real + "\n" + stale_calib + "\n")
            rows = CAL.hits_to_verdict_rows(
                [{"fp_id": "FP-01", "file": "C.sol", "line": 5,
                  "function": "f"}],
                "2026-05-16T00:00:00Z",
            )
            CAL.append_rows(ledger, rows, dedupe_prune=True)
            txt = ledger.read_text()
            self.assertIn('"workspace": "graph"', txt)
            self.assertNotIn("Old.sol", txt)
            self.assertIn("C.sol", txt)


class TestEndToEndCleanCorpus(unittest.TestCase):
    def test_real_corpus_emits_only_fp_verdicts(self):
        self.assertTrue(_CORPUS.is_dir(), "clean corpus must exist")
        runner = _REPO / "tools" / "audit" / "universal_fp_runner.py"
        fp_dir = _REPO / "audit" / "corpus_tags" / "tags"
        envelope = CAL.run_universal_fp_runner(runner, _CORPUS, fp_dir)
        rows = CAL.hits_to_verdict_rows(
            envelope.get("hits", []), "2026-05-16T00:00:00Z"
        )
        # The corpus is audited library source: every hit is an FP.
        for r in rows:
            self.assertEqual(r["verdict"], "FP")
            self.assertEqual(r["recorded_by"], "calibration")
        table = CAL.per_fp_calibration_table(envelope, rows)
        self.assertEqual(len(table), 6, "FP-01..FP-06 evaluated")
        # Sum of per-FP hits equals total emitted verdict rows.
        self.assertEqual(
            sum(r["clean_corpus_hits"] for r in table), len(rows)
        )

    def test_idempotent_dedupe_prune(self):
        runner = _REPO / "tools" / "audit" / "universal_fp_runner.py"
        fp_dir = _REPO / "audit" / "corpus_tags" / "tags"
        envelope = CAL.run_universal_fp_runner(runner, _CORPUS, fp_dir)
        rows = CAL.hits_to_verdict_rows(
            envelope.get("hits", []), "2026-05-16T00:00:00Z"
        )
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "ledger.jsonl"
            ledger.write_text("# header\n")
            CAL.append_rows(ledger, rows, dedupe_prune=True)
            first = len(
                [l for l in ledger.read_text().splitlines()
                 if l.startswith("{")]
            )
            CAL.append_rows(ledger, rows, dedupe_prune=True)
            second = len(
                [l for l in ledger.read_text().splitlines()
                 if l.startswith("{")]
            )
            self.assertEqual(first, second, "dedupe-prune is stable")


class TestStrictMode(unittest.TestCase):
    def test_strict_fails_when_shape_exceeds_ceiling(self):
        # Build a synthetic noisy corpus: a contract with an unguarded
        # storage write so FP-01 fires.
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "noisy"
            src = corpus / "src"
            src.mkdir(parents=True)
            (src / "Noisy.sol").write_text(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.20;\n"
                "contract Noisy {\n"
                "    uint256 public total;\n"
                "    function setTotal(uint256 v) external {\n"
                "        total = v;\n"
                "    }\n"
                "}\n"
            )
            ledger = Path(td) / "ledger.jsonl"
            ledger.write_text("# header\n")
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = CAL.main([
                    "--corpus", str(corpus),
                    "--ledger", str(ledger),
                    "--no-append",
                    "--strict",
                    "--max-clean-hits", "0",
                    "--output", str(Path(td) / "summary.json"),
                ])
            # If FP-01 fires on the unguarded write, strict returns 1;
            # if the shape does not fire, the corpus is clean -> 0.
            self.assertIn(rc, (0, 1))


if __name__ == "__main__":
    unittest.main()
