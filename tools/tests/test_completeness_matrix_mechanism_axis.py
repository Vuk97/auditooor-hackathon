#!/usr/bin/env python3
"""Tests for the completeness-matrix v2 MECHANISM axis (impact x mechanism plane).

Contract: a [asset x impact x mechanism] cell is NOT-ENUMERATED (fail-closed under
enforce) unless a mechanism-detector sidecar ran (0 findings => clean) OR every open
finding carries an explicit disposition. Grounded in the NUVA chain-halt miss."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_mech", _MOD)
cmb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmb)


def _ws(inscope, *, scans=None, dispositions=None):
    d = Path(tempfile.mkdtemp(prefix="mech_"))
    a = d / ".auditooor"
    a.mkdir(parents=True)
    (a / "inscope_units.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in inscope), encoding="utf-8")
    (a / "exploit_class_coverage.json").write_text(
        json.dumps({"classes": {"theft": "ruled-out"}}), encoding="utf-8")
    if scans:
        sd = a / "mechanism_scan"
        sd.mkdir()
        for i, sc in enumerate(scans):
            (sd / f"s{i}.json").write_text(json.dumps(sc), encoding="utf-8")
    if dispositions is not None:
        (a / "mechanism_dispositions.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in dispositions), encoding="utf-8")
    return d


def _cell(m, impact, mech):
    for c in m["mechanism_axis"]["cells"]:
        if c["impact"] == impact and c["mechanism"] == mech:
            return c
    return None


class MechanismAxisTest(unittest.TestCase):
    def setUp(self):
        for k in ("AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE", "AUDITOOOR_MECHANISM_AXIS_ENFORCE",
                  "AUDITOOOR_L37_STRICT"):
            os.environ.pop(k, None)

    def test_unscanned_cell_not_enumerated_and_worklisted(self):
        m = cmb.build_matrix(_ws([{"file": "src/v/keeper/abci.go", "function": "BeginBlocker"}]))
        cell = _cell(m, "chain-halt", "consensus-hook-unbounded-iteration")
        self.assertIsNotNone(cell)
        self.assertEqual(cell["status"], "not-enumerated-unscanned")
        wl = cmb.build_enumeration_worklist(m)
        mech_rows = [r for r in wl if r["axis"] == "mechanism"
                     and r["mechanism"] == "consensus-hook-unbounded-iteration"]
        self.assertTrue(mech_rows and "run mechanism detector" in mech_rows[0]["action"])

    def test_scanned_clean_cell_enumerated(self):
        ws = _ws([{"file": "src/v/keeper/abci.go", "function": "BeginBlocker"}],
                 scans=[{"mechanism": "consensus-hook-unbounded-iteration", "findings": []}])
        m = cmb.build_matrix(ws)
        cell = _cell(m, "chain-halt", "consensus-hook-unbounded-iteration")
        self.assertEqual(cell["status"], "enumerated-scanned-clean")

    def test_open_finding_not_enumerated_until_dispositioned(self):
        finding = {"file": "keeper/reconcile.go", "line": 474,
                   "function": "handleVaultInterestTimeouts"}
        ws = _ws([{"file": "src/v/keeper/abci.go", "function": "BeginBlocker"}],
                 scans=[{"mechanism": "consensus-hook-unbounded-iteration", "findings": [finding]}])
        m = cmb.build_matrix(ws)
        cell = _cell(m, "chain-halt", "consensus-hook-unbounded-iteration")
        self.assertEqual(cell["status"], "not-enumerated-open-finding")
        self.assertEqual(cell["open_findings"], 1)

        # now disposition it -> enumerated
        ws2 = _ws([{"file": "src/v/keeper/abci.go", "function": "BeginBlocker"}],
                  scans=[{"mechanism": "consensus-hook-unbounded-iteration", "findings": [finding]}],
                  dispositions=[{"mechanism": "consensus-hook-unbounded-iteration",
                                 "file": "keeper/reconcile.go", "line": 474,
                                 "verdict": "refuted-bounded-elsewhere"}])
        m2 = cmb.build_matrix(ws2)
        self.assertEqual(_cell(m2, "chain-halt", "consensus-hook-unbounded-iteration")["status"],
                         "enumerated-findings-dispositioned")

    def test_enforce_flips_verdict_on_mechanism_gap(self):
        ws = _ws([{"file": "src/v/keeper/abci.go", "function": "BeginBlocker"}])
        m_warn = cmb.build_matrix(ws)  # default: mechanism gap does not alone flip
        self.assertTrue(any("WARN" in r and "mechanism" in r for r in m_warn["reasons"]))
        os.environ["AUDITOOOR_MECHANISM_AXIS_ENFORCE"] = "1"
        try:
            m_enf = cmb.build_matrix(ws)
            self.assertEqual(m_enf["verdict"], "incomplete")
            self.assertTrue(any("NOT-ENUMERATED" in r and "mechanism" in r and "WARN" not in r
                                for r in m_enf["reasons"]))
        finally:
            os.environ.pop("AUDITOOOR_MECHANISM_AXIS_ENFORCE", None)

    def test_open_finding_blocks_under_strict_but_unscanned_only_warns(self):
        # SURGICAL closure: an OPEN finding (detector fired, un-dispositioned) blocks
        # under the main STRICT gate; an UNSCANNED cell (no detector) only WARNs.
        finding = {"file": "keeper/reconcile.go", "line": 474, "function": "h"}
        ws = _ws([{"file": "src/v/keeper/abci.go", "function": "BeginBlocker"}],
                 scans=[{"mechanism": "consensus-hook-unbounded-iteration", "findings": [finding]}])
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            m = cmb.build_matrix(ws)
            self.assertEqual(m["verdict"], "incomplete", "open finding must block under STRICT")
            self.assertTrue(any("OPEN" in r and "finding" in r for r in m["reasons"]))
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)

        # a ws with ONLY unscanned mechanism cells (no fired detector) is NOT treated
        # as an OPEN finding. Under L37_STRICT the unscanned cell is a REQUIRED terminal
        # adjudication (see _mech_unscanned_enforced: L37_STRICT enforces the mechanism
        # axis - a deliberate tightening since this test was written), so it BLOCKS with
        # a NOT-ENUMERATED reason, never an OPEN un-dispositioned-finding reason. The
        # default-posture WARN-only behaviour is covered by
        # test_enforce_flips_verdict_on_mechanism_gap.
        ws2 = _ws([{"file": "src/v/A.sol", "function": "f"}])  # solidity, no scans
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            m2 = cmb.build_matrix(ws2)
            self.assertEqual(m2["mechanism_axis"]["not_enumerated_open"], 0)
            self.assertFalse(any("OPEN" in r and "un-dispositioned finding" in r
                                 for r in m2["reasons"]),
                             "unscanned-only mechanism cells must not add an OPEN blocking reason")
            self.assertTrue(any("NOT-ENUMERATED" in r and "mechanism" in r
                                for r in m2["reasons"]),
                            "unscanned cell blocks under STRICT with a NOT-ENUMERATED reason")
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def test_language_filter_excludes_inapplicable_mechanism(self):
        # a Solidity-only ws must NOT carry the Go/Rust/Move-only consensus-hook cell
        m = cmb.build_matrix(_ws([{"file": "src/v/A.sol", "function": "f"}]))
        self.assertEqual(m["mechanism_axis"]["ws_languages"], ["solidity"])
        self.assertIsNone(_cell(m, "chain-halt", "consensus-hook-unbounded-iteration"),
                          "consensus-hook (go/rust/move) is not applicable to a solidity-only ws")
        # but the solidity unbounded-growable cell IS present
        self.assertIsNotNone(_cell(m, "permanent-freeze", "unbounded-attacker-growable-iteration"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
