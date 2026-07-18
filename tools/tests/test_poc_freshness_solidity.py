#!/usr/bin/env python3
"""Regression: poc-freshness-recheck.py catches a Solidity PoC that imports a source
file which no longer exists at the current pin (renamed/removed). Before this, the tool
only handled Go PoCs, so a Solidity-only workspace produced poc_count=0 and a VACUOUS
pass-poc-fresh - which let Strata's srt-haircut paste-ready (PoC importing the removed
`AccountingLib.sol`) sail through Check #138 (2026-07-07)."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "poc-freshness-recheck.py"
_spec = importlib.util.spec_from_file_location("poc_fresh", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class TestSolidityFreshness(unittest.TestCase):
    def _ws(self) -> Path:
        ws = Path(tempfile.mkdtemp())
        # current source tree: only Accounting.sol exists (AccountingLib.sol removed)
        src = ws / "src" / "contracts" / "contracts" / "tranches"
        src.mkdir(parents=True)
        (src / "Accounting.sol").write_text("// SPDX\npragma solidity 0.8.28;\ncontract Accounting {}\n")
        lib = ws / "src" / "contracts" / "lib" / "forge-std" / "src"
        lib.mkdir(parents=True)
        (lib / "Test.sol").write_text("contract Test {}\n")
        pr = ws / "submissions" / "paste_ready" / "f"
        pr.mkdir(parents=True)
        return ws, pr

    def test_stale_import_flagged(self):
        ws, pr = self._ws()
        (pr / "Poc.t.sol").write_text(
            'import {Test} from "forge-std/Test.sol";\n'
            'import {AccountingLib} from "../../../src/contracts/contracts/tranches/utils/AccountingLib.sol";\n'
            "contract Poc is Test {}\n")
        r = _m.recheck(ws)
        self.assertEqual(r["verdict"], "fail-stale-poc")
        self.assertEqual(r["stale_count"], 1)
        self.assertTrue(any("AccountingLib.sol" in d for res in r["results"] for d in res["drift"]))

    def test_fresh_import_passes(self):
        ws, pr = self._ws()
        (pr / "Poc.t.sol").write_text(
            'import {Test} from "forge-std/Test.sol";\n'
            'import {Accounting} from "../../../src/contracts/contracts/tranches/Accounting.sol";\n'
            "contract Poc is Test {}\n")
        r = _m.recheck(ws)
        self.assertEqual(r["verdict"], "pass-poc-fresh")
        self.assertEqual(r["stale_count"], 0)

    def test_inline_md_block_flagged(self):
        ws, pr = self._ws()
        (pr / "finding.md").write_text(
            "# finding\n\n```solidity\n"
            'import {AccountingLib} from "../contracts/tranches/utils/AccountingLib.sol";\n'
            "contract P {}\n```\n")
        r = _m.recheck(ws)
        self.assertEqual(r["verdict"], "fail-stale-poc")
        self.assertGreaterEqual(r["stale_count"], 1)

    def test_relative_helper_resolves_fresh(self):
        # a co-located helper imported relatively resolves on disk -> not flagged
        ws, pr = self._ws()
        (pr / "Helper.sol").write_text("contract Helper {}\n")
        (pr / "Poc.t.sol").write_text(
            'import {Helper} from "./Helper.sol";\n'
            'import {Accounting} from "../../../src/contracts/contracts/tranches/Accounting.sol";\n'
            "contract Poc {}\n")
        r = _m.recheck(ws)
        self.assertEqual(r["verdict"], "pass-poc-fresh")


if __name__ == "__main__":
    unittest.main()
