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
TOOL = ROOT / "tools" / "local-corpus-postinteraction-fee-detector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("local_corpus_postinteraction_fee_detector", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


VULNERABLE = """
pragma solidity ^0.8.20;

contract SettlementExtension {
    uint256 private constant _TAKING_FEE_BASE = 1e9;

    function _parseFeeData(bytes calldata extraData, uint256 actualTakingAmount)
        internal
        pure
        returns (address integrator, uint256 integrationFee)
    {
        integrator = address(bytes20(extraData[:20]));
        integrationFee = actualTakingAmount * uint256(uint32(bytes4(extraData[20:24]))) / _TAKING_FEE_BASE;
    }

    function postInteraction(Order calldata order, bytes calldata extraData, uint256 actualTakingAmount, address taker) external {
        (address integrator, uint256 integrationFee) = _parseFeeData(extraData, actualTakingAmount);
        order.takerAsset.safeTransferFrom(taker, integrator, integrationFee);
    }
}

struct Order { IERC20 takerAsset; }
interface IERC20 {
    function safeTransferFrom(address from, address to, uint256 value) external;
}
"""


CLEAN_CAPS_FEE_BPS = """
pragma solidity ^0.8.20;

contract SettlementExtension {
    uint256 private constant _TAKING_FEE_BASE = 1e9;

    function _parseFeeData(bytes calldata extraData, uint256 actualTakingAmount)
        internal
        pure
        returns (address integrator, uint256 integrationFee)
    {
        integrator = address(bytes20(extraData[:20]));
        uint256 feeBps = uint256(uint32(bytes4(extraData[20:24])));
        require(feeBps <= _TAKING_FEE_BASE, "fee too high");
        integrationFee = actualTakingAmount * feeBps / _TAKING_FEE_BASE;
    }

    function postInteraction(Order calldata order, bytes calldata extraData, uint256 actualTakingAmount, address taker) external {
        (address integrator, uint256 integrationFee) = _parseFeeData(extraData, actualTakingAmount);
        order.takerAsset.safeTransferFrom(taker, integrator, integrationFee);
    }
}

struct Order { IERC20 takerAsset; }
interface IERC20 { function safeTransferFrom(address from, address to, uint256 value) external; }
"""


CLEAN_THRESHOLD_IN_POST_INTERACTION = """
pragma solidity ^0.8.20;

contract SettlementExtension {
    uint256 private constant _TAKING_FEE_BASE = 1e9;

    function _parseFeeData(bytes calldata extraData, uint256 actualTakingAmount)
        internal
        pure
        returns (address integrator, uint256 integrationFee)
    {
        integrator = address(bytes20(extraData[:20]));
        integrationFee = actualTakingAmount * uint256(uint32(bytes4(extraData[20:24]))) / _TAKING_FEE_BASE;
    }

    function postInteraction(Order calldata order, bytes calldata extraData, uint256 actualTakingAmount, address taker, uint256 threshold) external {
        (address integrator, uint256 integrationFee) = _parseFeeData(extraData, actualTakingAmount);
        require(actualTakingAmount + integrationFee <= threshold, "threshold");
        order.takerAsset.safeTransferFrom(taker, integrator, integrationFee);
    }
}

struct Order { IERC20 takerAsset; }
interface IERC20 { function safeTransferFrom(address from, address to, uint256 value) external; }
"""


NO_POST_TRANSFER = """
pragma solidity ^0.8.20;

contract SettlementExtension {
    uint256 private constant _TAKING_FEE_BASE = 1e9;

    function _parseFeeData(bytes calldata extraData, uint256 actualTakingAmount)
        internal
        pure
        returns (address integrator, uint256 integrationFee)
    {
        integrator = address(bytes20(extraData[:20]));
        integrationFee = actualTakingAmount * uint256(uint32(bytes4(extraData[20:24]))) / _TAKING_FEE_BASE;
    }

    function postInteraction(bytes calldata extraData, uint256 actualTakingAmount) external pure returns (uint256) {
        (, uint256 integrationFee) = _parseFeeData(extraData, actualTakingAmount);
        return integrationFee;
    }
}
"""


class LocalCorpusPostInteractionFeeDetectorTests(unittest.TestCase):
    def test_detects_maker_controlled_extra_data_fee_in_post_interaction(self) -> None:
        hits = MOD.detect_source(VULNERABLE, "SettlementExtension.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].packet_id, "LCCR-PKT-011")
        self.assertEqual(hits[0].parse_function, "_parseFeeData")
        self.assertEqual(hits[0].post_function, "postInteraction")

    def test_skips_when_fee_basis_is_capped(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_CAPS_FEE_BPS, "SettlementExtension.sol"), [])

    def test_skips_when_post_interaction_applies_threshold(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_THRESHOLD_IN_POST_INTERACTION, "SettlementExtension.sol"), [])

    def test_skips_without_taker_fee_transfer(self) -> None:
        self.assertEqual(MOD.detect_source(NO_POST_TRANSFER, "SettlementExtension.sol"), [])

    def test_cli_emits_packet_payload_and_nonzero_on_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "SettlementExtension.sol"
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
            self.assertEqual(payload["selected_packet"], "LCCR-PKT-011")
            self.assertEqual(payload["hit_count"], 1)


if __name__ == "__main__":
    unittest.main()
