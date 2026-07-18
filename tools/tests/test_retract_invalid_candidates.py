#!/usr/bin/env python3
"""Regression: retract-invalid-candidates.py moves a paste-ready finding whose PoC
imports a REMOVED source file (stale at the current pin) out of paste_ready/ into
_killed/, so it stops blocking the workspace-wide pre-submit poc-freshness gate
(Strata 2026-07-07: srt-haircut imported the removed AccountingLib.sol and pinned
#138 fail, blocking a co-located valid Critical). Dry-run reports; --apply moves;
idempotent; a valid finding is never touched."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "retract-invalid-candidates.py"
_spec = importlib.util.spec_from_file_location("retract_invalid", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class TestRetractInvalid(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp())
        src = ws / "src" / "contracts" / "tranches"
        src.mkdir(parents=True)
        (src / "Accounting.sol").write_text("pragma solidity 0.8.28;\ncontract Accounting {}\n")
        (ws / "src" / "contracts" / "lib").mkdir(parents=True)
        (ws / "src" / "contracts" / "lib" / "Test.sol").write_text("contract Test {}\n")
        pr = ws / "submissions" / "paste_ready"
        # STALE candidate: PoC imports removed AccountingLib.sol
        stale = pr / "srt-haircut"
        stale.mkdir(parents=True)
        (stale / "Poc.t.sol").write_text(
            'import {Test} from "lib/Test.sol";\n'
            'import {AccountingLib} from "../../../src/contracts/tranches/utils/AccountingLib.sol";\n'
            "contract P is Test {}\n")
        (pr / "srt-haircut.md.hash").write_text("deadbeef")
        # VALID candidate: PoC imports an existing file
        good = pr / "good-finding"
        good.mkdir(parents=True)
        (good / "Poc.t.sol").write_text(
            'import {Accounting} from "../../../src/contracts/tranches/Accounting.sol";\n'
            "contract G {}\n")
        return ws

    def test_dry_run_reports_but_does_not_move(self):
        ws = self._ws()
        r = _m.retract(ws, apply=False)
        self.assertEqual(r["invalid_count"], 1)
        self.assertEqual(r["moved_count"], 0)
        self.assertEqual(r["invalid"][0]["name"], "srt-haircut")
        # still in place
        self.assertTrue((ws / "submissions" / "paste_ready" / "srt-haircut").is_dir())

    def test_apply_moves_stale_only(self):
        ws = self._ws()
        r = _m.retract(ws, apply=True)
        self.assertEqual(r["moved_count"], 1)
        # stale moved to _killed/, valid untouched
        self.assertFalse((ws / "submissions" / "paste_ready" / "srt-haircut").exists())
        self.assertTrue((ws / "submissions" / "_killed" / "srt-haircut").is_dir())
        self.assertTrue((ws / "submissions" / "_killed" / "srt-haircut" / "_RETRACTION.json").is_file())
        self.assertTrue((ws / "submissions" / "_killed" / "srt-haircut.md.hash").is_file())
        self.assertTrue((ws / "submissions" / "paste_ready" / "good-finding").is_dir())
        rec = json.loads((ws / "submissions" / "_killed" / "srt-haircut" / "_RETRACTION.json").read_text())
        self.assertEqual(rec["reason"], "stale-poc-removed-source-import")

    def test_idempotent_after_apply(self):
        ws = self._ws()
        _m.retract(ws, apply=True)
        r2 = _m.retract(ws, apply=True)
        self.assertEqual(r2["invalid_count"], 0)
        self.assertEqual(r2["verdict"], "none-invalid")

    def test_all_valid_workspace_noop(self):
        ws = self._ws()
        # remove the stale one first
        import shutil
        shutil.rmtree(ws / "submissions" / "paste_ready" / "srt-haircut")
        r = _m.retract(ws, apply=True)
        self.assertEqual(r["invalid_count"], 0)


if __name__ == "__main__":
    unittest.main()
