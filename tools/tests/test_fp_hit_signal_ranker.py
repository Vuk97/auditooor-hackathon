#!/usr/bin/env python3
"""Tests for tools/audit/fp-hit-signal-ranker.py (Wave-5 W5-C1).

Stdlib only. All fixtures are synthetic, written into a tempdir.

Coverage matrix:
  1. Basic ranking: production hit outranks a test hit (path term).
  2. Severity term: a theft attack-class outranks griefing.
  3. Rarity term: a 3x-firing shape outranks a 900x-firing shape.
  4. Precision: measured ledger precision overrides the confidence
     prior when the shape has >= min-verdicts scored verdicts.
  5. Graceful degradation: no --feedback => confidence-prior fallback,
     prec_source == 'confidence'.
  6. Sparse ledger: a shape below --min-verdicts falls back to the
     confidence prior (prec_source != 'measured').
  7. Deterministic order: ranks are 1..N, sorted score desc.
  8. Weight override: --weights re-normalises and is honoured.
  9. Empty hit list: valid envelope, total_hits 0.
 10. Markdown + JSON file output paths.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit" / "fp-hit-signal-ranker.py"


def _run(args, expect_rc=0):
    proc = subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if expect_rc is not None:
        assert proc.returncode == expect_rc, (
            "rc=%s\nstdout=%s\nstderr=%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    return proc


def _runner_envelope(hits, fps_evaluated=None):
    return {
        "schema": "auditooor.universal_fp_runner.v1",
        "target_workspace": "/tmp/ws-fixture",
        "total_hits": len(hits),
        "fps_evaluated": fps_evaluated or [],
        "hits": hits,
    }


def _hit(fp_id, file, line, classification, confidence, function=""):
    return {
        "fp_id": fp_id,
        "file": file,
        "line": line,
        "function": function,
        "snippet": "x",
        "confidence": confidence,
        "path_classification": classification,
    }


def _write(tmp, name, doc):
    p = Path(tmp) / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


class TestFpHitSignalRanker(unittest.TestCase):

    def test_1_production_outranks_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = _runner_envelope([
                _hit("FP-01", "src/Vault.sol", 10, "production", "medium"),
                _hit("FP-01", "test/Vault.t.sol", 20, "test", "medium"),
            ])
            rp = _write(tmp, "runner.json", runner)
            out = json.loads(_run(["--runner-output", str(rp)]).stdout)
            ranked = out["ranked_hits"]
            self.assertEqual(ranked[0]["path_classification"], "production")
            self.assertEqual(ranked[1]["path_classification"], "test")
            self.assertGreater(ranked[0]["score"], ranked[1]["score"])

    def test_2_severity_term(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = _runner_envelope(
                [
                    _hit("FP-01", "src/A.sol", 1, "production", "medium"),
                    _hit("FP-02", "src/B.sol", 1, "production", "medium"),
                ],
                fps_evaluated=[
                    {"fp_id": "FP-01", "attack_class": "theft-of-funds"},
                    {"fp_id": "FP-02", "attack_class": "griefing"},
                ],
            )
            rp = _write(tmp, "runner.json", runner)
            out = json.loads(_run(["--runner-output", str(rp)]).stdout)
            by_fp = {r["fp_id"]: r for r in out["ranked_hits"]}
            self.assertGreater(
                by_fp["FP-01"]["terms"]["sev"], by_fp["FP-02"]["terms"]["sev"]
            )
            self.assertEqual(by_fp["FP-01"]["rank"], 1)

    def test_3_rarity_term(self):
        with tempfile.TemporaryDirectory() as tmp:
            # FP-02 fires 5x, FP-09 fires 1x -> FP-09 rarer.
            hits = [
                _hit("FP-02", "src/A%d.sol" % i, 1, "production", "medium")
                for i in range(5)
            ]
            hits.append(_hit("FP-09", "src/Z.sol", 1, "production", "medium"))
            rp = _write(tmp, "runner.json", _runner_envelope(hits))
            out = json.loads(_run(["--runner-output", str(rp)]).stdout)
            by_fp = {}
            for r in out["ranked_hits"]:
                by_fp.setdefault(r["fp_id"], r)
            self.assertGreater(
                by_fp["FP-09"]["terms"]["rare"], by_fp["FP-02"]["terms"]["rare"]
            )

    def test_4_measured_precision_overrides_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = _runner_envelope([
                _hit("FP-01", "src/A.sol", 1, "production", "low"),
            ])
            feedback = {
                "schema": "auditooor.fp_tp_feedback_loop.v1",
                "per_fp": [
                    {"fp_id": "FP-01", "precision": 0.9,
                     "scored_verdicts": 5},
                ],
            }
            rp = _write(tmp, "runner.json", runner)
            fp = _write(tmp, "feedback.json", feedback)
            out = json.loads(_run([
                "--runner-output", str(rp), "--feedback", str(fp),
            ]).stdout)
            hit = out["ranked_hits"][0]
            self.assertEqual(hit["terms"]["prec_source"], "measured")
            self.assertEqual(hit["terms"]["prec"], 0.9)
            self.assertTrue(out["feedback_used"])

    def test_5_graceful_degradation_no_feedback(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = _runner_envelope([
                _hit("FP-01", "src/A.sol", 1, "production", "high"),
            ])
            rp = _write(tmp, "runner.json", runner)
            out = json.loads(_run(["--runner-output", str(rp)]).stdout)
            hit = out["ranked_hits"][0]
            self.assertEqual(hit["terms"]["prec_source"], "confidence")
            self.assertEqual(hit["terms"]["prec"], 0.85)
            self.assertFalse(out["feedback_used"])

    def test_6_sparse_ledger_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = _runner_envelope([
                _hit("FP-01", "src/A.sol", 1, "production", "medium"),
            ])
            feedback = {
                "schema": "auditooor.fp_tp_feedback_loop.v1",
                "per_fp": [
                    {"fp_id": "FP-01", "precision": 0.9,
                     "scored_verdicts": 2},  # below --min-verdicts=3
                ],
            }
            rp = _write(tmp, "runner.json", runner)
            fp = _write(tmp, "feedback.json", feedback)
            out = json.loads(_run([
                "--runner-output", str(rp), "--feedback", str(fp),
            ]).stdout)
            hit = out["ranked_hits"][0]
            self.assertNotEqual(hit["terms"]["prec_source"], "measured")
            self.assertEqual(hit["terms"]["prec"], 0.55)  # medium prior

    def test_7_deterministic_rank_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            hits = [
                _hit("FP-01", "src/A.sol", 1, "production", "high"),
                _hit("FP-01", "test/B.t.sol", 2, "test", "low"),
                _hit("FP-01", "src/C.sol", 3, "mock", "medium"),
            ]
            rp = _write(tmp, "runner.json", _runner_envelope(hits))
            out = json.loads(_run(["--runner-output", str(rp)]).stdout)
            ranked = out["ranked_hits"]
            self.assertEqual([r["rank"] for r in ranked], [1, 2, 3])
            scores = [r["score"] for r in ranked]
            self.assertEqual(scores, sorted(scores, reverse=True))

    def test_8_weight_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = _runner_envelope([
                _hit("FP-01", "src/A.sol", 1, "production", "high"),
            ])
            rp = _write(tmp, "runner.json", runner)
            out = json.loads(_run([
                "--runner-output", str(rp),
                "--weights", "prec=0.5,path=0.5,sev=0,rare=0",
            ]).stdout)
            w = out["weights"]
            self.assertAlmostEqual(sum(w.values()), 1.0, places=6)
            self.assertAlmostEqual(w["prec"], 0.5, places=6)
            self.assertAlmostEqual(w["sev"], 0.0, places=6)

    def test_9_empty_hit_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            rp = _write(tmp, "runner.json", _runner_envelope([]))
            out = json.loads(_run(["--runner-output", str(rp)]).stdout)
            self.assertEqual(out["total_hits"], 0)
            self.assertEqual(out["ranked_hits"], [])

    def test_10_file_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = _runner_envelope([
                _hit("FP-01", "src/A.sol", 1, "production", "high"),
            ])
            rp = _write(tmp, "runner.json", runner)
            jout = Path(tmp) / "ranked.json"
            mout = Path(tmp) / "ranked.md"
            _run([
                "--runner-output", str(rp),
                "--json-out", str(jout), "--md-out", str(mout),
            ])
            self.assertTrue(jout.is_file())
            self.assertTrue(mout.is_file())
            doc = json.loads(jout.read_text())
            self.assertEqual(doc["schema"], "auditooor.fp_hit_signal_ranker.v1")
            md = mout.read_text()
            self.assertIn("fp-hit-signal-ranker report", md)
            self.assertIn("Top 1 hits", md)


if __name__ == "__main__":
    unittest.main()
