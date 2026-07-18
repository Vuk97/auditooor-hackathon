#!/usr/bin/env python3
"""GEN-D consensus-nondeterministic-return-ordering screen tests.

Non-vacuity is anchored on a REAL fleet mutation pair (polygon cosmos-sdk
x/nft/keeper/genesis.go ExportGenesis): the real file sorts `owners` before the
genesis-export return -> SILENT; deleting `sort.Strings(owners)` -> FIRES a
genesis-export/high row. The real file is never mutated on disk (a temp copy is
used); the test skips if the polygon tree is absent.

NOTE: this cap was authored by a build subagent whose distinct-adversarial-verify
was cut short by a weekly usage limit; the verification here (fixtures + real-fleet
mutation + FP-control probes) was performed in the main loop as the distinct
reviewer. See the commit message.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
SCREEN = TOOLS / "consensus-map-order-return-screen.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "gen_d"
POLY_GENESIS = Path(
    "/Users/wolf/audits/polygon/src/cosmos-sdk/x/nft/keeper/genesis.go")


def _scan_file(path):
    out = subprocess.run(
        [sys.executable, str(SCREEN), "--file", str(path)],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


class TestGenD(unittest.TestCase):
    def test_fire_endblock_validatorupdate(self):
        rows = _scan_file(FIX / "fire_endblock.go")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["return_sink"], "validator-update")
        self.assertEqual(rows[0]["severity"], "high")

    def test_benign_dominating_sort_silent(self):
        # sort.Slice(updates,...) before the return suppresses the row.
        self.assertEqual(len(_scan_file(FIX / "benign_sorted.go")), 0)

    def test_benign_keyed_map_write_silent(self):
        # m[k] = append(...) is an order-invariant distinct-key accumulation,
        # never a returned ordered slice -> must NOT fire.
        self.assertEqual(len(_scan_file(FIX / "benign_keyedwrite.go")), 0)

    def test_benign_local_slice_silent(self):
        # slice used only for a local len() computation, never returned.
        self.assertEqual(len(_scan_file(FIX / "benign_local.go")), 0)

    def test_advisory_exit_and_schema(self):
        rows = _scan_file(FIX / "fire_endblock.go")
        r = rows[0]
        self.assertEqual(r["schema"],
                         "auditooor.consensus_map_order_return_hypotheses.v1")
        self.assertEqual(r["capability"], "GEN_D")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])

    @unittest.skipUnless(POLY_GENESIS.exists(),
                         "polygon cosmos-sdk tree absent")
    def test_real_fleet_mutation_pair(self):
        # (1) real ExportGenesis sorts `owners` before the genesis return -> silent
        self.assertEqual(len(_scan_file(POLY_GENESIS)), 0)
        # (2) delete the dominating sort on a temp copy -> newly fires
        with tempfile.TemporaryDirectory() as d:
            mut = Path(d) / "genesis.go"
            src = POLY_GENESIS.read_text()
            mutated = src.replace("\tsort.Strings(owners)\n", "")
            self.assertNotEqual(mutated, src, "mutation did not apply")
            mut.write_text(mutated)
            rows = _scan_file(mut)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["return_sink"], "genesis-export")
            self.assertEqual(rows[0]["severity"], "high")
            self.assertEqual(rows[0]["slice_var"], "owners")
        # (3) real file never touched
        self.assertIn("sort.Strings(owners)", POLY_GENESIS.read_text())

    def test_equivalent_mutant_keeps_sort_stays_silent(self):
        # guard-dominance teeth: a whitespace-only edit that KEEPS the sort
        # must remain silent (not a tautology that fires on any change).
        if not POLY_GENESIS.exists():
            self.skipTest("polygon tree absent")
        with tempfile.TemporaryDirectory() as d:
            eq = Path(d) / "genesis.go"
            src = POLY_GENESIS.read_text()
            eq.write_text(src.replace("sort.Strings(owners)",
                                      "sort.Strings(owners) // keep"))
            self.assertEqual(len(_scan_file(eq)), 0)


if __name__ == "__main__":
    unittest.main()
