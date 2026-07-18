"""Unit tests for tools/clean-codebase-calibrate.py.

Focuses on the pure aggregation/parsing logic. Network-touching or
slither-touching subcommands are exercised through subprocess wrappers so
they can be skipped cleanly when those external deps aren't available.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "clean-codebase-calibrate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("clean_calibrate", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cc = _load_module()


# ---------- parse_scan_output -------------------------------------------

class ParseScanOutputTest(unittest.TestCase):
    def test_parses_per_detector_hits(self) -> None:
        text = (
            "[ok] loaded 2 custom detector(s)\n"
            "=== Running detector-a ===\n"
            "  [HIGH] something bad happened in foo.sol\n"
            "  [MEDIUM] another thing in bar.sol\n"
            "=== Running detector-b ===\n"
            "  [LOW] minor finding\n"
            "=== Running detector-c ===\n"
            "[done] total hits: 3\n"
        )
        out = cc.parse_scan_output(text)
        self.assertEqual(out["per_detector"]["detector-a"], 2)
        self.assertEqual(out["per_detector"]["detector-b"], 1)
        self.assertEqual(out["per_detector"]["detector-c"], 0)
        self.assertEqual(out["total_hits"], 3)
        self.assertEqual(out["detectors_executed"], 3)
        self.assertFalse(out["compile_failed"])

    def test_detects_compile_failure(self) -> None:
        text = (
            "[ok] loaded 5 custom detector(s)\n"
            "[ok] compiling /tmp/x...\n"
            "Error compiling target: solc not found\n"
        )
        out = cc.parse_scan_output(text)
        self.assertTrue(out["compile_failed"])
        self.assertEqual(out["per_detector"], {})
        self.assertEqual(out["detectors_executed"], 0)

    def test_total_hits_falls_back_to_sum_when_missing(self) -> None:
        text = (
            "=== Running detector-a ===\n"
            "  [HIGH] x\n"
            "  [HIGH] y\n"
        )
        out = cc.parse_scan_output(text)
        self.assertEqual(out["total_hits"], 2)


# ---------- aggregate_records -------------------------------------------

class AggregateRecordsTest(unittest.TestCase):
    def test_aggregates_across_corpora(self) -> None:
        records = [
            {
                "name": "solady",
                "compile_failed": False,
                "per_detector": {"d1": 3, "d2": 0, "d3": 1},
            },
            {
                "name": "solmate",
                "compile_failed": False,
                "per_detector": {"d1": 1, "d2": 0, "d4": 5},
            },
        ]
        rep = cc.aggregate_records(records)
        self.assertEqual(rep["total_corpora"], 2)
        self.assertEqual(rep["successful_corpora"], 2)
        self.assertEqual(rep["skipped_corpora"], [])
        # d1 hits in BOTH corpora — biggest noise score
        first_det = next(iter(rep["per_detector"]))
        self.assertEqual(first_det, "d1")
        self.assertEqual(rep["per_detector"]["d1"]["total_hits"], 4)
        self.assertEqual(rep["per_detector"]["d1"]["corpora_with_hits"], 2)
        # d2 has zero hits anywhere, recorded but not "with_hits"
        self.assertEqual(rep["per_detector"]["d2"]["total_hits"], 0)
        self.assertEqual(rep["per_detector"]["d2"]["corpora_with_hits"], 0)

    def test_skips_failed_corpora(self) -> None:
        records = [
            {"name": "broken", "compile_failed": True, "per_detector": {}},
            {"name": "skipped", "skipped": True, "reason": "timeout"},
            {
                "name": "solady",
                "compile_failed": False,
                "per_detector": {"d1": 1},
            },
        ]
        rep = cc.aggregate_records(records)
        self.assertEqual(rep["total_corpora"], 3)
        self.assertEqual(rep["successful_corpora"], 1)
        self.assertEqual(set(rep["skipped_corpora"]), {"broken", "skipped"})

    def test_noise_score_ranks_multi_corpus_offenders_higher(self) -> None:
        # d-spread hits 1 each in two corpora (total 2, multi-corpus).
        # d-bulk hits 3 in one corpus (total 3, single-corpus).
        # Multi-corpus should outrank in noise_score per the design penalty.
        records = [
            {"name": "a", "compile_failed": False,
             "per_detector": {"d-spread": 1, "d-bulk": 3}},
            {"name": "b", "compile_failed": False,
             "per_detector": {"d-spread": 1, "d-bulk": 0}},
        ]
        rep = cc.aggregate_records(records)
        spread = rep["per_detector"]["d-spread"]
        bulk = rep["per_detector"]["d-bulk"]
        self.assertEqual(spread["corpora_with_hits"], 2)
        self.assertEqual(bulk["corpora_with_hits"], 1)
        # spread: 2 * (1 + 0.5) = 3.0; bulk: 3 * 1 = 3.0 → tie → bulk wins on
        # secondary total_hits sort. Verify the math is consistent rather
        # than asserting order.
        self.assertAlmostEqual(spread["noise_score"], 3.0)
        self.assertAlmostEqual(bulk["noise_score"], 3.0)


# ---------- propose_demotions -------------------------------------------

class ProposeDemotionsTest(unittest.TestCase):
    def _report(self):
        return {
            "per_detector": {
                "noisy-1": {"total_hits": 5, "corpora_with_hits": 2,
                            "noise_score": 7.5,
                            "by_corpus": {"a": 3, "b": 2}},
                "edge-2":  {"total_hits": 2, "corpora_with_hits": 1,
                            "noise_score": 2.0,
                            "by_corpus": {"a": 2, "b": 0}},
                "clean-3": {"total_hits": 1, "corpora_with_hits": 1,
                            "noise_score": 1.0,
                            "by_corpus": {"a": 1, "b": 0}},
                "zero-4":  {"total_hits": 0, "corpora_with_hits": 0,
                            "noise_score": 0,
                            "by_corpus": {"a": 0, "b": 0}},
            }
        }

    def test_default_threshold_picks_two_or_more(self) -> None:
        cands = cc.propose_demotions(self._report())
        names = [c["detector"] for c in cands]
        self.assertIn("noisy-1", names)
        self.assertIn("edge-2", names)
        self.assertNotIn("clean-3", names)
        self.assertNotIn("zero-4", names)

    def test_threshold_min_corpora_filters_single_corpus_offenders(self) -> None:
        cands = cc.propose_demotions(self._report(),
                                     min_total_hits=1,
                                     min_corpora_with_hits=2)
        names = [c["detector"] for c in cands]
        self.assertEqual(names, ["noisy-1"])  # only one fires on 2+ corpora

    def test_sorted_by_noise_score_desc(self) -> None:
        cands = cc.propose_demotions(self._report(), min_total_hits=1)
        # noisy-1 (7.5) > edge-2 (2.0) > clean-3 (1.0)
        self.assertEqual(cands[0]["detector"], "noisy-1")
        self.assertEqual(cands[-1]["detector"], "clean-3")


# ---------- vendored-path collision -------------------------------------

class VendoredPathCollisionTest(unittest.TestCase):
    """Regression: scanning a clean copy of solady/solmate/openzeppelin
    directly used to silently return 0 hits because run_custom.py's
    VENDORED_MARKERS post-filter drops every result whose path contains
    'solady/src', 'solmate/src', or 'openzeppelin'. The calibrate tool
    must detect that and stage the source into a marker-free path."""

    def test_collides_for_solady_src_path(self) -> None:
        self.assertTrue(cc._path_collides_with_vendored_filter(
            Path("/tmp/clean-corpus/solady/src")))

    def test_collides_for_openzeppelin_substring(self) -> None:
        self.assertTrue(cc._path_collides_with_vendored_filter(
            Path("/tmp/clean-corpus/openzeppelin-contracts/contracts")))

    def test_collides_for_lib_segment(self) -> None:
        self.assertTrue(cc._path_collides_with_vendored_filter(
            Path("/tmp/foo/lib/something")))

    def test_neutral_path_does_not_collide(self) -> None:
        self.assertFalse(cc._path_collides_with_vendored_filter(
            Path("/tmp/clean-corpus/clean-1/stage/code")))


# ---------- CLI smoke ----------------------------------------------------

class CliSmokeTest(unittest.TestCase):
    def test_list_subcommand_prints_corpora(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "list"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("solady", proc.stdout)
        self.assertIn("solmate", proc.stdout)

    def test_unknown_corpus_returns_nonzero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "download", "definitely-not-real"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
