#!/usr/bin/env python3
"""EXT2-01 mid-transition snapshot phase-freshness screen - regression + mutation.

Pins tools/mid-transition-snapshot-phase-freshness-screen.py: a non-view fn that
CONSUMES a cross-layer snapshot/proof, references a LOWER-LAYER TRANSIENT field,
and drives an authoritative CREDIT sink WITHOUT a phase-freshness guard rejecting
the transition window (activationEpoch/exitEpoch == FAR_FUTURE_EPOCH,
effectiveBalance == 0, pending/exiting status) fires (verdict=needs-fuzz);
a covered fn (guard present) or a non-enforcement-point fn stays silent.

Three non-vacuity legs (each guard is load-bearing):
  1. PLANTED POSITIVE  - proof-consumes + credits, NO phase guard -> fires.
  2. COVERED NEGATIVE  - same fn WITH `activationEpoch != FAR_FUTURE_EPOCH`
                         + `effectiveBalance > 0` guard -> silent.
                         Plus a pure proof-verifier (no transient/sink) -> silent.
  3. NEUTRALISE        - monkeypatch the CORE PREDICATE `_has_phase_guard` to a
                         constant True -> the planted positive STOPS firing
                         (proves the phase-guard check is load-bearing, not the
                         enforcement-point shape alone).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "mid_transition_snapshot_phase_freshness_screen",
        TOOLS / "mid-transition-snapshot-phase-freshness-screen.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- fixtures --------------------------------------------------------------- #

# POSITIVE: consumes a beacon-chain validator proof + credits shares from its
# effectiveBalance, but the ONLY freshness check is an AGE check (block.timestamp)
# - no PHASE guard rejecting a mid-transition (queued / FAR_FUTURE) validator.
POSITIVE = """
pragma solidity 0.8.25;

contract StakingBridge {
    mapping(address => uint256) public shares;

    function verifyAndCreditShares(
        bytes32[] calldata validatorFields,
        bytes calldata validatorProof,
        bytes32 beaconStateRoot,
        uint64 refSlotTimestamp,
        address staker
    ) external {
        require(block.timestamp - refSlotTimestamp < 86400, "stale");
        _verifyProof(validatorProof, beaconStateRoot, validatorFields);
        uint64 effectiveBalance = _getEffectiveBalance(validatorFields);
        shares[staker] += uint256(effectiveBalance);
    }

    function _verifyProof(bytes calldata p, bytes32 root, bytes32[] calldata f)
        internal view {}

    function _getActivationEpoch(bytes32[] calldata f)
        internal pure returns (uint64) { return uint64(uint256(f[0])); }

    function _getEffectiveBalance(bytes32[] calldata f)
        internal pure returns (uint64) { return uint64(uint256(f[1])); }
}
"""

# COVERED: identical shape but the credit is gated on a PHASE-freshness guard
# (activationEpoch != FAR_FUTURE_EPOCH AND effectiveBalance > 0) -> silent.
COVERED = """
pragma solidity 0.8.25;

contract StakingBridgeGuarded {
    uint64 internal constant FAR_FUTURE_EPOCH = type(uint64).max;
    mapping(address => uint256) public shares;

    function verifyAndCreditShares(
        bytes32[] calldata validatorFields,
        bytes calldata validatorProof,
        bytes32 beaconStateRoot,
        uint64 refSlotTimestamp,
        address staker
    ) external {
        require(block.timestamp - refSlotTimestamp < 86400, "stale");
        _verifyProof(validatorProof, beaconStateRoot, validatorFields);
        uint64 activationEpoch = _getActivationEpoch(validatorFields);
        uint64 effectiveBalance = _getEffectiveBalance(validatorFields);
        require(activationEpoch != FAR_FUTURE_EPOCH, "mid-transition");
        require(effectiveBalance > 0, "queued");
        shares[staker] += uint256(effectiveBalance);
    }

    function _verifyProof(bytes calldata p, bytes32 root, bytes32[] calldata f)
        internal view {}

    function _getActivationEpoch(bytes32[] calldata f)
        internal pure returns (uint64) { return uint64(uint256(f[0])); }

    function _getEffectiveBalance(bytes32[] calldata f)
        internal pure returns (uint64) { return uint64(uint256(f[1])); }
}
"""

# NON-EP: a pure proof verifier with NO transient field and NO credit sink.
NON_EP = """
pragma solidity 0.8.25;

contract ProofVerifier {
    function verifyStateRoot(bytes calldata proof, bytes32 beaconStateRoot)
        external pure returns (bool) {
        return keccak256(proof) == beaconStateRoot;
    }
}
"""


def _scan(mod, src: str, name="Fixture.sol"):
    return mod.scan_file(pathlib.Path(name), name, file_text=src)


class Ext201MatrixTest(unittest.TestCase):
    def setUp(self):
        self.mod = _load_tool()

    # ---- leg 1: planted positive fires ---------------------------------- #
    def test_positive_fires(self):
        rows = _scan(self.mod, POSITIVE)
        fired = [r for r in rows if r["fires"]]
        self.assertEqual(len(fired), 1, f"expected exactly 1 fired point: {rows}")
        r = fired[0]
        self.assertEqual(r["function"], "verifyAndCreditShares")
        self.assertEqual(r["capability"], "EXT2_01")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        self.assertFalse(r["has_phase_guard"])
        # the age-vs-phase gap: it DOES carry an age check yet still fires.
        self.assertTrue(r["has_age_freshness"])
        self.assertTrue(r["snapshot_tokens"])
        self.assertTrue(r["transient_tokens"])
        self.assertTrue(r["sink_tokens"])

    # ---- leg 2: covered / benign negatives stay silent ------------------ #
    def test_covered_silent(self):
        rows = _scan(self.mod, COVERED)
        fired = [r for r in rows if r["fires"]]
        self.assertEqual(len(fired), 0, f"guarded fn must not fire: {fired}")
        # the point IS enumerated as an enforcement point, just guarded.
        eps = [r for r in rows if r["function"] == "verifyAndCreditShares"]
        self.assertEqual(len(eps), 1)
        self.assertTrue(eps[0]["has_phase_guard"])
        self.assertIn("far_future_epoch", eps[0]["phase_guard_kinds"])

    def test_non_enforcement_point_silent(self):
        rows = _scan(self.mod, NON_EP)
        # no transient field + no credit sink -> not even an enforcement point.
        self.assertEqual(rows, [], f"pure verifier must not be an EP: {rows}")

    # ---- leg 3: neutralise the core predicate stops the positive -------- #
    def test_neutralise_core_predicate_stops_positive(self):
        # sanity: fires before neutralising.
        self.assertEqual(
            sum(r["fires"] for r in _scan(self.mod, POSITIVE)), 1)
        # monkeypatch the CORE PREDICATE to a constant "guard always present".
        self.mod._has_phase_guard = lambda text: (True, ["forced"])
        rows = _scan(self.mod, POSITIVE)
        self.assertEqual(
            sum(r["fires"] for r in rows), 0,
            "with _has_phase_guard forced True the positive must NOT fire "
            "(the phase-guard predicate is the load-bearing check)")

    # ---- sidecar / workspace wiring ------------------------------------- #
    def test_workspace_emits_advisory_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "StakingBridge.sol").write_text(POSITIVE)
            rc = self.mod.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0, "default run exits 0 (advisory-first)")
            side = ws / ".auditooor" / \
                "mid_transition_snapshot_phase_freshness_hypotheses.jsonl"
            self.assertTrue(side.exists(), "sidecar must be written under .auditooor")
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            self.assertTrue(any(r["fires"] for r in rows))
            for r in rows:
                self.assertEqual(r["capability"], "EXT2_01")
                self.assertTrue(r["advisory"])
                self.assertFalse(r["auto_credit"])
                self.assertEqual(r["verdict"], "needs-fuzz")

    def test_strict_exit_code_on_fire(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "StakingBridge.sol").write_text(POSITIVE)
            rc = self.mod.main(["--workspace", str(ws), "--strict"])
            self.assertEqual(rc, 1, "--strict must exit 1 when a point fired")

    def test_source_mode_prints_no_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            (d / "StakingBridge.sol").write_text(POSITIVE)
            rc = self.mod.main(["--source", str(d)])
            self.assertEqual(rc, 0)
            self.assertFalse((d / ".auditooor").exists(),
                             "--source must NOT write a sidecar")


if __name__ == "__main__":
    unittest.main()
