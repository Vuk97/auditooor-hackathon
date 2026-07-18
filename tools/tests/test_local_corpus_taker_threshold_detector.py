#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "local-corpus-taker-threshold-detector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("local_corpus_taker_threshold_detector", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


VULNERABLE = """
pragma solidity ^0.8.20;

contract OrderMixin {
    function _fillOrderTo(Order calldata order, TakerTraits takerTraits, uint256 amount) internal {
        uint256 remainingMakingAmount = 100 ether;
        bytes32 orderHash = bytes32(uint256(1));
        bytes calldata extension = msg.data;
        uint256 makingAmount;
        uint256 takingAmount;

        if (takerTraits.isMakingAmount()) {
            makingAmount = amount;
            takingAmount = order.calculateTakingAmount(
                extension,
                makingAmount,
                remainingMakingAmount,
                orderHash
            );
            uint256 threshold = takerTraits.threshold();
            if (threshold > 0) {
                if (takingAmount > threshold) revert TakingAmountTooHigh();
            }
        } else {
            takingAmount = amount;
            makingAmount = order.calculateMakingAmount(
                extension,
                takingAmount,
                remainingMakingAmount,
                orderHash
            );
            uint256 threshold = takerTraits.threshold();
            if (threshold > 0) {
                if (makingAmount < threshold) revert MakingAmountTooLow();
            }
        }
    }
}

type TakerTraits is uint256;

using TakerTraitsLib for TakerTraits global;
using OrderLib for Order global;

struct Order {}

library TakerTraitsLib {
    function isMakingAmount(TakerTraits) internal pure returns (bool) { return true; }
    function threshold(TakerTraits) internal pure returns (uint256) { return 0; }
}

library OrderLib {
    function calculateTakingAmount(Order calldata, bytes calldata, uint256, uint256, bytes32) internal pure returns (uint256) { return 1; }
    function calculateMakingAmount(Order calldata, bytes calldata, uint256, uint256, bytes32) internal pure returns (uint256) { return 1; }
}

error TakingAmountTooHigh();
error MakingAmountTooLow();
"""


CLEAN_REQUIRES_THRESHOLD = """
pragma solidity ^0.8.20;

contract OrderMixin {
    function _fillOrderTo(Order calldata order, TakerTraits takerTraits, uint256 amount) internal {
        uint256 makingAmount = order.calculateMakingAmount(msg.data, amount, amount, bytes32(0));
        uint256 threshold = takerTraits.threshold();
        require(threshold > 0, "threshold required");
        if (threshold > 0) {
            if (makingAmount < threshold) revert MakingAmountTooLow();
        }
    }
}

type TakerTraits is uint256;
using TakerTraitsLib for TakerTraits global;
using OrderLib for Order global;
struct Order {}
library TakerTraitsLib { function threshold(TakerTraits) internal pure returns (uint256) { return 1; } }
library OrderLib { function calculateMakingAmount(Order calldata, bytes calldata, uint256, uint256, bytes32) internal pure returns (uint256) { return 1; } }
error MakingAmountTooLow();
"""


CLEAN_DEFAULTS_THRESHOLD = """
pragma solidity ^0.8.20;

contract OrderMixin {
    function _fillOrderTo(Order calldata order, TakerTraits takerTraits, uint256 amount) internal {
        uint256 makingAmount = order.calculateMakingAmount(msg.data, amount, amount, bytes32(0));
        uint256 threshold = takerTraits.threshold();
        if (threshold == 0) threshold = amount;
        if (threshold > 0) {
            if (makingAmount < threshold) revert MakingAmountTooLow();
        }
    }
}

type TakerTraits is uint256;
using TakerTraitsLib for TakerTraits global;
using OrderLib for Order global;
struct Order {}
library TakerTraitsLib { function threshold(TakerTraits) internal pure returns (uint256) { return 0; } }
library OrderLib { function calculateMakingAmount(Order calldata, bytes calldata, uint256, uint256, bytes32) internal pure returns (uint256) { return 1; } }
error MakingAmountTooLow();
"""


NO_CALLBACK = """
pragma solidity ^0.8.20;

contract PlainThreshold {
    function fill(TakerTraits takerTraits, uint256 amount) external pure returns (uint256) {
        uint256 threshold = takerTraits.threshold();
        if (threshold > 0 && amount > threshold) revert TooMuch();
        return amount;
    }
}

type TakerTraits is uint256;
using TakerTraitsLib for TakerTraits global;
library TakerTraitsLib { function threshold(TakerTraits) internal pure returns (uint256) { return 0; } }
error TooMuch();
"""


class LocalCorpusTakerThresholdDetectorTests(unittest.TestCase):
    def test_detects_optional_zero_threshold_around_amount_callbacks(self) -> None:
        hits = MOD.detect_source(VULNERABLE, "OrderMixin.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].packet_id, "LCCR-PKT-002")
        self.assertEqual(hits[0].function, "_fillOrderTo")
        self.assertEqual(hits[0].threshold_variable, "threshold")

    def test_skips_when_threshold_is_required(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_REQUIRES_THRESHOLD, "OrderMixin.sol"), [])

    def test_skips_when_zero_threshold_gets_defaulted(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_DEFAULTS_THRESHOLD, "OrderMixin.sol"), [])

    def test_skips_non_callback_threshold_guard(self) -> None:
        self.assertEqual(MOD.detect_source(NO_CALLBACK, "PlainThreshold.sol"), [])

    def test_cli_emits_packet_payload_and_nonzero_on_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "OrderMixin.sol"
            fixture.write_text(VULNERABLE, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(fixture)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["selected_packet"], "LCCR-PKT-002")
            self.assertEqual(payload["hit_count"], 1)


if __name__ == "__main__":
    unittest.main()
