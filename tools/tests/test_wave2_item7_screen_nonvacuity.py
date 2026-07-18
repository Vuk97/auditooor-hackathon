#!/usr/bin/env python3
"""Wave-2 item-7 NON-VACUITY tests for the four anti-vacuity screen transforms.

The capability-vacuity telltale (see memory
`methodology_capability_vacuity_telltale.md`): a screen whose FIRED survivors are
emitted `advisory=True` drains SILENTLY to advisory-green when a downstream
`_is_advisory_row` filter buckets them - the fired obligation never counts as
OPEN. The item-7 fix: a real survivor (`fires==True` / `severity_eligible==True`)
is emitted `advisory=False` + `proof_status='open'` so it is counted OPEN;
`fires==False` enumeration leads stay `advisory=True`.

This module asserts, per screen, BOTH legs:
  * a synthetic FIRED survivor row -> advisory==False, proof_status=='open', and
    a downstream advisory filter counts it OPEN (not advisory);
  * a non-fired enumeration lead -> advisory==True and the same filter counts it
    advisory.

The four screens:
  - transmute-type-confusion-screen.py            (GEN_R3, rust)
  - release-silent-overflow-screen.py             (GEN_R5, rust)
  - cross-layer-cardinality-divergence-screen.py  (EXT04, sol/go)
  - verifier-executor-divergence-screen.py        (EXT03, rust/go/c/sol)
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
TRANSMUTE = TOOLS / "transmute-type-confusion-screen.py"
RELEASE = TOOLS / "release-silent-overflow-screen.py"
CARDINALITY = TOOLS / "cross-layer-cardinality-divergence-screen.py"
VERIFIER = TOOLS / "verifier-executor-divergence-screen.py"


def _is_advisory_row(row: dict) -> bool:
    """Model of a downstream advisory filter: an OPEN obligation
    (proof_status=='open') is NOT advisory (it must be counted OPEN); everything
    else falls back to the row's advisory flag (default True)."""
    if row.get("proof_status") == "open":
        return False
    return bool(row.get("advisory", True))


def _run_file(scanner: Path, src: str, suffix: str) -> list:
    """Run a screen in --file mode, return the emitted rows (unwrapping the
    EXT03 {summary, rows} shape when present)."""
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as fh:
        fh.write(textwrap.dedent(src))
        path = fh.name
    proc = subprocess.run(
        [sys.executable, str(scanner), "--file", path],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"{scanner.name} rc={proc.returncode}\n{proc.stderr}"
    out = json.loads(proc.stdout)
    if isinstance(out, dict) and "rows" in out:
        return out["rows"]
    return out


class TransmuteFiredSurvivorOpen(unittest.TestCase):
    """GEN_R3: a bytes->bool transmute is a fired survivor -> advisory=False,
    proof_status=open, counted OPEN by the downstream filter."""

    SRC = """
    fn reinterpret(x: u8) -> bool {
        unsafe { std::mem::transmute::<u8, bool>(x) }
    }
    """

    def test_fired_row_is_open_not_advisory(self):
        rows = _run_file(TRANSMUTE, self.SRC, ".rs")
        fired = [r for r in rows if r.get("fires")]
        self.assertTrue(fired, "expected a fired bytes-to-niche survivor")
        for r in fired:
            self.assertFalse(r["advisory"], f"fired row must be advisory=False: {r}")
            self.assertEqual(r.get("proof_status"), "open")
            self.assertFalse(_is_advisory_row(r),
                             "downstream filter must count fired survivor OPEN")


class ReleaseFiredSurvivorOpen(unittest.TestCase):
    """GEN_R5: untrusted decode-read wrapping into with_capacity is a fired
    survivor -> advisory=False, proof_status=open, counted OPEN."""

    SRC = """
    pub fn parse(buf: &[u8]) -> Vec<u8> {
        let n = read_u32(buf);
        let total = n * 4;
        Vec::with_capacity(total as usize)
    }
    """

    def test_fired_row_is_open_not_advisory(self):
        rows = _run_file(RELEASE, self.SRC, ".rs")
        fired = [r for r in rows if r.get("fires")]
        self.assertTrue(fired, "expected a fired untrusted-wrap-into-sink survivor")
        for r in fired:
            self.assertFalse(r["advisory"], f"fired row must be advisory=False: {r}")
            self.assertEqual(r.get("proof_status"), "open")
            self.assertFalse(_is_advisory_row(r),
                             "downstream filter must count fired survivor OPEN")


class CardinalityFiredVsLead(unittest.TestCase):
    """EXT04: a same-function commit/settle cardinality divergence FIRES (open),
    while a benign two-loop-same-bound buffer stays a fires==False advisory."""

    POSITIVE = """
    pragma solidity ^0.8.0;
    contract Settlement {
        function settle(bytes32[] calldata txs, uint256 numRealTxs) external {
            for (uint256 i = 0; i < txs.length; i++) { _commit(txs[i]); }
            for (uint256 j = 0; j < numRealTxs; j++) { _settle(txs[j]); }
        }
        function _commit(bytes32 x) internal {}
        function _settle(bytes32 x) internal {}
    }
    """

    NEGATIVE = """
    pragma solidity ^0.8.0;
    contract Benign {
        function loop(bytes32[] calldata txs) external {
            for (uint256 i = 0; i < txs.length; i++) { _a(txs[i]); }
            for (uint256 j = 0; j < txs.length; j++) { _b(txs[j]); }
        }
        function _a(bytes32 x) internal {}
        function _b(bytes32 x) internal {}
    }
    """

    def test_fired_divergence_is_open(self):
        rows = _run_file(CARDINALITY, self.POSITIVE, ".sol")
        fired = [r for r in rows if r.get("fires")]
        self.assertTrue(fired, "expected a same-function divergence fire")
        for r in fired:
            self.assertFalse(r["advisory"], f"fired row must be advisory=False: {r}")
            self.assertEqual(r.get("proof_status"), "open")
            self.assertFalse(_is_advisory_row(r))

    def test_nonfired_lead_stays_advisory(self):
        rows = _run_file(CARDINALITY, self.NEGATIVE, ".sol")
        self.assertTrue(rows, "expected an enforcement-point row for the benign buffer")
        nonfired = [r for r in rows if not r.get("fires")]
        self.assertTrue(nonfired, "expected a non-fired enumeration lead")
        for r in nonfired:
            self.assertTrue(r["advisory"], f"non-fired lead must stay advisory=True: {r}")
            self.assertNotEqual(r.get("proof_status"), "open")
            self.assertTrue(_is_advisory_row(r),
                            "downstream filter must count non-fired lead advisory")


class VerifierFiredVsLead(unittest.TestCase):
    """EXT03: a width-mismatch codegen arm is severity-eligible (open), while the
    hand-picked-encoding enumeration lead stays a fires==False advisory."""

    # codegen_role via `opcode`; a match arm declares S64 but emits Rb (8-bit).
    SRC = """
    // opcode encoder
    fn emit(sz: Size) {
        match sz {
            Size::S32 => { Rd(reg); }
            Size::S64 => { Rb(reg); }
        }
    }
    """

    def test_fired_mismatch_is_open(self):
        rows = _run_file(VERIFIER, self.SRC, ".rs")
        fired = [r for r in rows if r.get("severity_eligible")]
        self.assertTrue(fired, "expected a severity-eligible width-mismatch fire")
        for r in fired:
            self.assertTrue(r.get("fires"))
            self.assertFalse(r["advisory"], f"fired row must be advisory=False: {r}")
            self.assertEqual(r.get("proof_status"), "open")
            self.assertFalse(_is_advisory_row(r))

    def test_lead_stays_advisory(self):
        rows = _run_file(VERIFIER, self.SRC, ".rs")
        leads = [r for r in rows if not r.get("fires")
                 and not r.get("severity_eligible")]
        self.assertTrue(leads, "expected a handpicked-encoding enumeration lead")
        for r in leads:
            self.assertTrue(r["advisory"], f"lead must stay advisory=True: {r}")
            self.assertNotEqual(r.get("proof_status"), "open")
            self.assertTrue(_is_advisory_row(r))


if __name__ == "__main__":
    unittest.main()
