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
TOOL = ROOT / "tools" / "local-corpus-callback-rescue-detector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("local_corpus_callback_rescue_detector", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


VULNERABLE_CURVE = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function curveSwapCallback(
        address,
        address,
        address inCoin,
        uint256 dx,
        uint256
    ) external {
        IERC20(inCoin).safeTransfer(msg.sender, dx);
    }
}

interface IERC20 {
    function safeTransfer(address to, uint256 value) external;
}
"""


VULNERABLE_UNISWAP_SELF_PAYER = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function uniswapV3SwapCallback(int256 amount0Delta, int256, bytes calldata data) external {
        (address payer, address token) = abi.decode(data, (address, address));
        if (payer == address(this)) {
            IERC20(token).safeTransfer(msg.sender, uint256(amount0Delta));
        }
    }
}

interface IERC20 {
    function safeTransfer(address to, uint256 value) external;
}
"""


VULNERABLE_UNISWAP_ASSEMBLY_SELF_PAYER = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata) external override {
        amount0Delta;
        amount1Delta;
        assembly ("memory-safe") {
            let emptyPtr := mload(0x40)
            let payer := calldataload(0x84)
            let token := calldataload(0x24)
            switch eq(payer, address())
            case 1 {
                mstore(add(emptyPtr, add(_TRANSFER_SELECTOR_OFFSET, 0x04)), caller())
                mstore(add(emptyPtr, add(_TRANSFER_SELECTOR_OFFSET, 0x24)), 100)
                safeERC20(token, 0, add(emptyPtr, _TRANSFER_SELECTOR_OFFSET), 0x44, 0x20)
            }
        }
    }
}
"""


CLEAN_CURVE_AUTHENTICATES_POOL = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    address immutable curvePool;

    function curveSwapCallback(address, address, address inCoin, uint256 dx, uint256) external {
        require(msg.sender == curvePool, "pool");
        IERC20(inCoin).safeTransfer(msg.sender, dx);
    }
}

interface IERC20 {
    function safeTransfer(address to, uint256 value) external;
}
"""


CLEAN_UNISWAP_VERIFY_CALLBACK = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function uniswapV3SwapCallback(int256 amount0Delta, int256, bytes calldata data) external {
        CallbackValidation.verifyCallback(factory, data);
        (address payer, address token) = abi.decode(data, (address, address));
        if (payer == address(this)) {
            IERC20(token).safeTransfer(msg.sender, uint256(amount0Delta));
        }
    }
}

library CallbackValidation {
    function verifyCallback(address, bytes calldata) internal view {}
}

interface IERC20 {
    function safeTransfer(address to, uint256 value) external;
}
"""


TRANSFER_FROM_EXTERNAL_PAYER = """
pragma solidity ^0.8.20;

contract Router {
    function uniswapV3SwapCallback(int256 amount0Delta, int256, bytes calldata data) external {
        (address payer, address token) = abi.decode(data, (address, address));
        IERC20(token).transferFrom(payer, msg.sender, uint256(amount0Delta));
    }
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 value) external;
}
"""


class LocalCorpusCallbackRescueDetectorTests(unittest.TestCase):
    def test_detects_permissionless_curve_callback_transfer_to_caller(self) -> None:
        hits = MOD.detect_source(VULNERABLE_CURVE, "UnoswapRouter.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].packet_id, "LCCR-PKT-012")
        self.assertEqual(hits[0].callback_function, "curveSwapCallback")
        self.assertEqual(hits[0].sink_kind, "curve-callback-direct-transfer-to-caller")

    def test_detects_permissionless_uniswap_self_payer_branch(self) -> None:
        hits = MOD.detect_source(VULNERABLE_UNISWAP_SELF_PAYER, "UnoswapRouter.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].callback_function, "uniswapV3SwapCallback")
        self.assertEqual(hits[0].sink_kind, "uniswap-v3-self-payer-transfer-to-caller")

    def test_detects_permissionless_uniswap_assembly_self_payer_branch(self) -> None:
        hits = MOD.detect_source(VULNERABLE_UNISWAP_ASSEMBLY_SELF_PAYER, "UnoswapRouter.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].callback_function, "uniswapV3SwapCallback")
        self.assertEqual(hits[0].sink_kind, "uniswap-v3-self-payer-transfer-to-caller")

    def test_skips_curve_callback_with_pool_authentication(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_CURVE_AUTHENTICATES_POOL, "UnoswapRouter.sol"), [])

    def test_skips_uniswap_callback_with_verify_callback(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_UNISWAP_VERIFY_CALLBACK, "UnoswapRouter.sol"), [])

    def test_skips_transfer_from_external_payer_shape(self) -> None:
        self.assertEqual(MOD.detect_source(TRANSFER_FROM_EXTERNAL_PAYER, "Router.sol"), [])

    def test_cli_emits_packet_payload_and_nonzero_on_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "UnoswapRouter.sol"
            fixture.write_text(VULNERABLE_CURVE + VULNERABLE_UNISWAP_SELF_PAYER, encoding="utf-8")
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
            self.assertEqual(payload["selected_packet"], "LCCR-PKT-012")
            self.assertEqual(payload["hit_count"], 2)


if __name__ == "__main__":
    unittest.main()
