#!/usr/bin/env python3
"""Tests for tools/pipeline-rediscovery-measure.py scoring logic.

These tests exercise score_case() and function_spans() with synthetic inputs
(no network, no real corpus run). The forward-test / full-pipeline behavior is
validated by the live run; these lock the SCORING contract:
  - the novel-vector miner grants ONLY line-level credit (no file-level),
  - corpus-driven-hunt grants file-level + line-level,
  - a line-level hit requires landing inside the bug's function span (miner)
    or within +/-line_tol (hunt),
  - honest misses stay misses.
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "pipeline_rediscovery_measure",
    Path(__file__).resolve().parent.parent / "pipeline-rediscovery-measure.py",
)
prm = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(prm)


def _write(tmp, name, text):
    p = Path(tmp) / name
    p.write_text(text, encoding="utf-8")
    return p


SOL_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    uint256 public total;          // line 4
    function deposit(uint256 a) external {   // line 5
        total += a;                // line 6
    }                              // line 7
    function withdraw(uint256 a) external {  // line 8
        total -= a;                // line 9 (BUG line)
    }                              // line 10
}
"""

RS_SRC = """pub fn verify_header(h: Header) -> bool {   // line 1
    if h.epoch == 0 { return false; }       // line 2
    check_supermajority(h)                  // line 3 (BUG line)
}                                           // line 4
pub fn other() {}                           // line 5
"""


class TestFunctionSpans(unittest.TestCase):
    def test_solidity_spans(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "Vault.sol", SOL_SRC)
            spans = prm.function_spans(p, "solidity")
            names = {n for n, _, _ in spans}
            self.assertEqual(names, {"deposit", "withdraw"})
            self.assertEqual(prm.fn_span_containing(spans, 9), "withdraw")
            self.assertEqual(prm.fn_span_containing(spans, 6), "deposit")

    def test_rust_spans(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "lib.rs", RS_SRC)
            spans = prm.function_spans(p, "rust")
            names = {n for n, _, _ in spans}
            self.assertIn("verify_header", names)
            self.assertEqual(prm.fn_span_containing(spans, 3), "verify_header")


class TestScoreCase(unittest.TestCase):
    def _case(self, tmp, fname, line):
        return {
            "case_id": "synthetic--x",
            "vuln_class": "fund-theft",
            "language": "solidity",
            "split": "TRAIN",
            "file_line": f"{fname}:{line}",
            "local_checkout": tmp,
        }

    def test_miner_line_hit_no_file_credit(self):
        """Miner targets withdraw (span contains BUG line 9) -> line hit.
        Miner must NOT grant file-level credit (harness pointed it at file)."""
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "Vault.sol", SOL_SRC)
            case = self._case(tmp, "Vault.sol", 9)
            nv = {"invariants": [{"function": "withdraw"}, {"function": "deposit"}]}
            hunt = {"hypotheses": []}  # hunt cites nothing
            r = prm.score_case(case, nv, hunt, line_tol=25)
            self.assertTrue(r["rediscovered_line"])
            self.assertEqual(r["surfacing_stage"], "novel-vector-fn-span")
            # HONESTY: no hunt cite => no file-level credit despite miner running
            self.assertFalse(r["rediscovered_file"])
            self.assertTrue(r["nv_ran_on_file"])

    def test_miner_targets_wrong_fn_is_miss(self):
        """Miner targets only deposit; BUG is in withdraw (line 9) -> line miss."""
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "Vault.sol", SOL_SRC)
            case = self._case(tmp, "Vault.sol", 9)
            nv = {"invariants": [{"function": "deposit"}]}
            hunt = {"hypotheses": []}
            r = prm.score_case(case, nv, hunt, line_tol=25)
            self.assertFalse(r["rediscovered_line"])
            self.assertFalse(r["rediscovered_file"])

    def test_hunt_candidate_fn_line_hit(self):
        """Hunt candidate_function cites the file within tol -> file+line hit."""
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "Vault.sol", SOL_SRC)
            case = self._case(tmp, "Vault.sol", 9)
            nv = {"invariants": []}
            hunt = {"hypotheses": [{
                "candidate_functions": [{"fn": "withdraw", "file": "Vault.sol", "line": 8}],
                "in_target_evidence": [],
            }]}
            r = prm.score_case(case, nv, hunt, line_tol=25)
            self.assertTrue(r["rediscovered_file"])
            self.assertTrue(r["rediscovered_line"])
            self.assertEqual(r["surfacing_stage"], "corpus-hunt-candidate-fn")

    def test_hunt_file_only_weak(self):
        """Hunt cites the file but at a far line -> file-level only (weak)."""
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "Vault.sol", SOL_SRC)
            case = self._case(tmp, "Vault.sol", 9)
            nv = {"invariants": []}
            hunt = {"hypotheses": [{
                "candidate_functions": [],
                "in_target_evidence": [{"keyword": "x", "file": "Vault.sol", "line": 500, "fn": None}],
            }]}
            r = prm.score_case(case, nv, hunt, line_tol=25)
            self.assertTrue(r["rediscovered_file"])
            self.assertFalse(r["rediscovered_line"])

    def test_wrong_file_is_miss(self):
        """Hunt cites a DIFFERENT file -> no credit at all."""
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "Vault.sol", SOL_SRC)
            case = self._case(tmp, "Vault.sol", 9)
            nv = {"invariants": []}
            hunt = {"hypotheses": [{
                "candidate_functions": [{"fn": "f", "file": "Other.sol", "line": 9}],
                "in_target_evidence": [],
            }]}
            r = prm.score_case(case, nv, hunt, line_tol=25)
            self.assertFalse(r["rediscovered_file"])
            self.assertFalse(r["rediscovered_line"])


class TestSummarize(unittest.TestCase):
    def test_rates_by_split_and_class(self):
        results = [
            {"split": "TRAIN", "class": "a", "rediscovered_file": True, "rediscovered_line": True},
            {"split": "TRAIN", "class": "a", "rediscovered_file": True, "rediscovered_line": False},
            {"split": "HELD_OUT", "class": "b", "rediscovered_file": False, "rediscovered_line": False},
        ]
        s = prm.summarize(results)
        self.assertEqual(s["overall"]["n"], 3)
        self.assertAlmostEqual(s["by_split"]["TRAIN"]["rediscovery_line"], 0.5)
        self.assertEqual(s["by_split"]["HELD_OUT"]["rediscovery_line"], 0.0)


if __name__ == "__main__":
    unittest.main()
