#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "zero_signal_drain.py"


def _load_detector():
    module_name = "zero_signal_drain_detector"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec and spec.loader, f"failed to load {DETECTOR_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


VULNERABLE_SOURCE = """
pragma solidity ^0.8.20;

contract L2GNSLike {
    mapping(bytes32 => bool) public curatedTargets;
    mapping(bytes32 => uint256) public targetSignal;
    uint256 public curatedReserve;

    function publishNewVersion(bytes32 target, uint256 assets) external {
        require(curatedTargets[target], "CURATED_TARGET");
        uint256 vSignal = assets * targetSignal[target] / curatedReserve;
        targetSignal[target] += vSignal;
    }

    function burnSignal(bytes32 target, uint256 signalAmount) external {
        require(signalAmount > 0, "ZERO_SIGNAL_BURN");
        uint256 payout = curatedReserve * signalAmount / targetSignal[target];
        _transferReserve(msg.sender, payout);
    }

    function _transferReserve(address to, uint256 amount) internal {}
}
"""


CLEAN_SOURCE = """
pragma solidity ^0.8.20;

contract L2GNSLikeFixed {
    mapping(bytes32 => bool) public curatedTargets;
    mapping(bytes32 => uint256) public targetSignal;
    uint256 public curatedReserve;

    function publishNewVersion(bytes32 target, uint256 assets) external {
        require(curatedTargets[target], "CURATED_TARGET");
        uint256 vSignal = assets * targetSignal[target] / curatedReserve;
        require(vSignal > 0, "ZERO_SIGNAL_MINT");
        targetSignal[target] += vSignal;
    }

    function burnSignal(bytes32 target, uint256 signalAmount) external {
        require(signalAmount > 0, "ZERO_SIGNAL_BURN");
        uint256 payout = curatedReserve * signalAmount / targetSignal[target];
        _transferReserve(msg.sender, payout);
    }

    function _transferReserve(address to, uint256 amount) internal {}
}
"""


NO_RESERVE_PAYOUT_SOURCE = """
pragma solidity ^0.8.20;

contract L2GNSLikeNoDrain {
    mapping(bytes32 => bool) public curatedTargets;
    mapping(bytes32 => uint256) public targetSignal;
    uint256 public curatedReserve;

    function publishNewVersion(bytes32 target, uint256 assets) external {
        require(curatedTargets[target], "CURATED_TARGET");
        uint256 vSignal = assets * targetSignal[target] / curatedReserve;
        targetSignal[target] += vSignal;
    }

    function burnSignal(bytes32 target, uint256 signalAmount) external pure {
        require(signalAmount > 0, "ZERO_SIGNAL_BURN");
        target;
    }
}
"""


class ZeroSignalDrainDetectorTest(unittest.TestCase):
    def test_fires_on_graph_like_shape(self) -> None:
        mod = _load_detector()
        findings = mod.scan(VULNERABLE_SOURCE, "L2GNSLike.sol")
        self.assertGreaterEqual(len(findings), 1)
        first = findings[0]
        self.assertEqual(first.detector, "zero-signal-drain")
        self.assertEqual(first.severity, "High")
        self.assertEqual(first.function, "publishNewVersion")
        self.assertIn("zero-signal-drain", first.message)

    def test_skips_when_positive_output_guard_exists(self) -> None:
        mod = _load_detector()
        findings = mod.scan(CLEAN_SOURCE, "L2GNSLikeFixed.sol")
        self.assertEqual(findings, [])

    def test_skips_when_burn_side_has_no_reserve_payout_shape(self) -> None:
        mod = _load_detector()
        findings = mod.scan(NO_RESERVE_PAYOUT_SOURCE, "L2GNSLikeNoDrain.sol")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
