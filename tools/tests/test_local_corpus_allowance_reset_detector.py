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
TOOL = ROOT / "tools" / "local-corpus-allowance-reset-detector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("local_corpus_allowance_reset_detector", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


VULNERABLE = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function _curfe(address fromToken, address pool, uint256 amount) internal {
        bytes4 selector = bytes4(0x095ea7b3);
        selector;
        // fromToken.approve(pool, amount)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x095ea7b300000000000000000000000000000000000000000000000000000000)
            mstore(add(ptr, 0x04), pool)
            mstore(add(ptr, 0x24), amount)
        }
        safeERC20(fromToken, 0, abi.encode(pool));
        curveExchange(pool);
    }

    function safeERC20(address, uint256, bytes memory) internal {}
    function curveExchange(address) internal {}
}
"""


CLEAN_RESET = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function _curfe(IERC20 fromToken, address pool, uint256 amount) internal {
        fromToken.approve(pool, amount);
        curveExchange(pool);
        fromToken.approve(pool, 0);
    }

    function curveExchange(address) internal {}
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}
"""


NON_CURVE_APPROVE = """
pragma solidity ^0.8.20;

contract PlainAllowance {
    function approveSpender(IERC20 token, address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}
"""


class LocalCorpusAllowanceResetDetectorTests(unittest.TestCase):
    def test_detects_curve_pool_approval_without_reset(self) -> None:
        hits = MOD.detect_source(VULNERABLE, "UnoswapRouter.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].packet_id, "LCCR-PKT-001")
        self.assertEqual(hits[0].function, "_curfe")

    def test_skips_curve_pool_approval_with_zero_reset(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_RESET, "UnoswapRouter.sol"), [])

    def test_skips_non_curve_plain_approval(self) -> None:
        self.assertEqual(MOD.detect_source(NON_CURVE_APPROVE, "PlainAllowance.sol"), [])

    def test_cli_emits_packet_payload_and_nonzero_on_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "UnoswapRouter.sol"
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
            self.assertEqual(payload["selected_packet"], "LCCR-PKT-001")
            self.assertEqual(payload["hit_count"], 1)


if __name__ == "__main__":
    unittest.main()
