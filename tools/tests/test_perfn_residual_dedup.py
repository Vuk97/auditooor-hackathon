#!/usr/bin/env python3
"""Regression test for the per-fn-mimo-batch-gen residual dedup (Strata 2026-07-07).

The scoped hunt must dispatch the coverage RESIDUAL, not the already-closed surface:
a task whose exact (unit, hypothesis) already has a GENUINE terminal sidecar
(status=ok + applies_to_target in {yes,no}) is dropped; a NON-terminal sidecar
(maybe / halted / errored) and a same-unit-NEW-hypothesis task both stay huntable.
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "per-fn-mimo-batch-gen.py"
_spec = importlib.util.spec_from_file_location("perfn_batch_gen", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


def _sidecar(ws: Path, name: str, file: str, fn: str, sqid: str,
             status="ok", applies="no", error=None):
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(parents=True, exist_ok=True)
    rec = {
        "status": status,
        "source_question_id": sqid,
        "function_anchor": {"file": file, "fn": fn},
        "result": json.dumps({"applies_to_target": applies}) if applies else None,
    }
    if error:
        rec["error"] = error
    (d / f"{name}.json").write_text(json.dumps(rec))


class TestResidualDedup(unittest.TestCase):
    def _ws(self):
        return Path(tempfile.mkdtemp())

    def test_terminal_only_enters_skip_set(self):
        ws = self._ws()
        F = "/x/src/Accounting.sol"
        _sidecar(ws, "a_no", F, "calculateNAVSplit", "crit:sum", applies="no")     # terminal
        _sidecar(ws, "b_yes", F, "updateBalanceFlow", "crit:sum", applies="yes")   # terminal
        _sidecar(ws, "c_maybe", F, "maxWithdraw", "crit:sum", applies="maybe")     # NON-terminal
        _sidecar(ws, "d_halted", F, "maxDeposit", "crit:sum", status="halted", applies=None)
        _sidecar(ws, "e_err", F, "srtNav", "crit:sum", error="auth-failed", applies="no")
        keys = _m._terminal_disposition_keys(ws)
        self.assertIn(("Accounting.sol", "calculateNAVSplit", "crit:sum"), keys)
        self.assertIn(("Accounting.sol", "updateBalanceFlow", "crit:sum"), keys)
        # non-terminal / stub sidecars MUST NOT suppress an unhunted unit
        self.assertNotIn(("Accounting.sol", "maxWithdraw", "crit:sum"), keys)
        self.assertNotIn(("Accounting.sol", "maxDeposit", "crit:sum"), keys)
        self.assertNotIn(("Accounting.sol", "srtNav", "crit:sum"), keys)
        self.assertEqual(len(keys), 2)

    def test_filter_drops_dupe_keeps_new_hypothesis(self):
        ws = self._ws()
        F = "/x/src/Accounting.sol"
        _sidecar(ws, "a_no", F, "calculateNAVSplit", "crit:sum", applies="no")
        skip = _m._terminal_disposition_keys(ws)

        def key_of(task):
            a = task["function_anchor"]
            return (os.path.basename(a["file"]), _m._base_fn(a["fn"]), task["source_question_id"])

        dupe = {"function_anchor": {"file": F, "fn": "Accounting.calculateNAVSplit(uint256)"},
                "source_question_id": "crit:sum"}
        new_hyp = {"function_anchor": {"file": F, "fn": "calculateNAVSplit"},
                   "source_question_id": "high:freeze"}   # SAME unit, DIFFERENT hypothesis
        other = {"function_anchor": {"file": F, "fn": "totalAssets"},
                 "source_question_id": "crit:sum"}
        self.assertIn(key_of(dupe), skip)         # dropped
        self.assertNotIn(key_of(new_hyp), skip)   # kept - new hypothesis
        self.assertNotIn(key_of(other), skip)     # kept - unhunted unit

    def test_no_sidecar_dir_is_empty_skipset(self):
        self.assertEqual(_m._terminal_disposition_keys(self._ws()), set())

    def test_base_fn_normalization(self):
        self.assertEqual(_m._base_fn("Accounting.calculateNAVSplit(uint256,uint256)"), "calculateNAVSplit")
        self.assertEqual(_m._base_fn("File::fn"), "fn")
        self.assertEqual(_m._base_fn("bareFn"), "bareFn")


if __name__ == "__main__":
    unittest.main()
