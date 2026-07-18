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
TOOL = ROOT / "tools" / "local-corpus-unoswap-curve-approve-mismatch-detector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("local_corpus_unoswap_curve_approve_mismatch_detector", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


VULNERABLE_UNOSWAP_CURFE = """
pragma solidity ^0.8.20;

type Address is uint256;

library ProtocolLib {
    enum Protocol { UniswapV3, Curve }
    function protocol(Address) internal pure returns (Protocol) {}
    function usePermit2(Address) internal pure returns (bool) {}
}

contract UnoswapRouter {
    using ProtocolLib for Address;

    function _unoswap(
        address spender,
        address recipient,
        Address token,
        uint256 amount,
        uint256 minReturn,
        Address dex
    ) private returns(uint256 returnAmount) {
        ProtocolLib.Protocol protocol = dex.protocol();
        if (protocol == ProtocolLib.Protocol.Curve) {
            if (spender == msg.sender && msg.value == 0) {
                IERC20(Address.unwrap(token)).safeTransferFromUniversal(msg.sender, address(this), amount, dex.usePermit2());
            }
            returnAmount = _curfe(recipient, amount, minReturn, dex);
        }
    }

    function _curfe(address recipient, uint256 amount, uint256 minReturn, Address dex) internal returns(uint256 ret) {
        address pool = address(uint160(Address.unwrap(dex)));
        address fromToken = ICurvePool(pool).coins(0);
        if (recipient != address(0) && minReturn > 0) {
            asmApprove(fromToken, pool, amount, mloadPtr());
        }
    }

    function asmApprove(address token, address spender, uint256 amount, uint256 ptr) private {}
    function mloadPtr() private pure returns (uint256) {}
}

interface IERC20 {
    function safeTransferFromUniversal(address from, address to, uint256 value, bool permit2) external;
}

interface ICurvePool {
    function coins(uint256 i) external view returns (address);
}
"""


VULNERABLE_SOLIDITY_APPROVE = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function _unoswap(address recipient, address token, uint256 amount, address dex) private {
        if (Protocol.Curve == protocolOf(dex)) {
            IERC20(token).transferFrom(msg.sender, address(this), amount);
            _curveSwap(recipient, amount, 1, dex);
        }
    }

    function _curveSwap(address, uint256 amount, uint256, address dex) internal {
        address pool = dex;
        address fromToken = ICurvePool(pool).coins(0);
        IERC20(fromToken).approve(pool, amount);
    }

    function protocolOf(address) private pure returns (Protocol) {}
}

enum Protocol { Uni, Curve }
interface IERC20 { function transferFrom(address, address, uint256) external; function approve(address, uint256) external; }
interface ICurvePool { function coins(uint256) external view returns (address); }
"""


CLEAN_PASSES_TOKEN_TO_CURFE = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function _unoswap(address recipient, address token, uint256 amount, address dex) private {
        if (Protocol.Curve == protocolOf(dex)) {
            IERC20(token).transferFrom(msg.sender, address(this), amount);
            _curfe(recipient, token, amount, 1, dex);
        }
    }

    function _curfe(address, address token, uint256 amount, uint256, address dex) internal {
        address pool = dex;
        address fromToken = ICurvePool(pool).coins(0);
        require(fromToken == token, "token mismatch");
        IERC20(fromToken).approve(pool, amount);
    }

    function protocolOf(address) private pure returns (Protocol) {}
}

enum Protocol { Uni, Curve }
interface IERC20 { function transferFrom(address, address, uint256) external; function approve(address, uint256) external; }
interface ICurvePool { function coins(uint256) external view returns (address); }
"""


CLEAN_APPROVES_DECLARED_TOKEN = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function _unoswap(address recipient, address token, uint256 amount, address dex) private {
        if (Protocol.Curve == protocolOf(dex)) {
            IERC20(token).transferFrom(msg.sender, address(this), amount);
            _curfe(recipient, amount, 1, dex);
        }
    }

    function _curfe(address, uint256 amount, uint256, address dex) internal {
        address pool = dex;
        address token = trustedInputToken[dex];
        IERC20(token).approve(pool, amount);
    }

    mapping(address => address) trustedInputToken;
    function protocolOf(address) private pure returns (Protocol) {}
}

enum Protocol { Uni, Curve }
interface IERC20 { function transferFrom(address, address, uint256) external; function approve(address, uint256) external; }
"""


CLEAN_NO_ROUTER_PULL = """
pragma solidity ^0.8.20;

contract UnoswapRouter {
    function _unoswap(address recipient, address, uint256 amount, address dex) private {
        if (Protocol.Curve == protocolOf(dex)) {
            _curfe(recipient, amount, 1, dex);
        }
    }

    function _curfe(address, uint256 amount, uint256, address dex) internal {
        address pool = dex;
        address fromToken = ICurvePool(pool).coins(0);
        IERC20(fromToken).approve(pool, amount);
    }

    function protocolOf(address) private pure returns (Protocol) {}
}

enum Protocol { Uni, Curve }
interface IERC20 { function approve(address, uint256) external; }
interface ICurvePool { function coins(uint256) external view returns (address); }
"""


class SolidityFilesFilterTests(unittest.TestCase):
    """Regression tests for test-file exclusion in solidity_files()."""

    def _write(self, base, rel: str, content: str):
        from pathlib import Path
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_t_sol_files_excluded_from_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._write(base, "prod/Router.sol", VULNERABLE_UNOSWAP_CURFE)
            self._write(base, "test/Router.t.sol", VULNERABLE_UNOSWAP_CURFE)
            hits = MOD.scan_paths([base])
            self.assertEqual(len(hits), 1, "test fixture must be excluded")
            self.assertNotIn(".t.sol", hits[0].path)

    def test_s_sol_files_excluded_from_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._write(base, "src/Router.sol", VULNERABLE_UNOSWAP_CURFE)
            self._write(base, "script/Deploy.s.sol", VULNERABLE_UNOSWAP_CURFE)
            hits = MOD.scan_paths([base])
            self.assertEqual(len(hits), 1, "script fixture must be excluded")
            self.assertNotIn(".s.sol", hits[0].path)

    def test_test_sol_files_excluded_from_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._write(base, "src/Router.sol", VULNERABLE_UNOSWAP_CURFE)
            self._write(base, "src/Router.test.sol", VULNERABLE_UNOSWAP_CURFE)
            hits = MOD.scan_paths([base])
            self.assertEqual(len(hits), 1, "*.test.sol must be excluded")
            self.assertNotIn(".test.sol", hits[0].path)

    def test_test_directory_files_excluded_from_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._write(base, "src/Router.sol", VULNERABLE_UNOSWAP_CURFE)
            self._write(base, "tests/Router.sol", VULNERABLE_UNOSWAP_CURFE)
            hits = MOD.scan_paths([base])
            self.assertEqual(len(hits), 1, "/tests/ directory files must be excluded")
            self.assertNotIn("tests/Router", hits[0].path)

    def test_t_sol_file_excluded_when_passed_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fixture = self._write(base, "Router.t.sol", VULNERABLE_UNOSWAP_CURFE)
            hits = MOD.scan_paths([fixture])
            self.assertEqual(len(hits), 0, ".t.sol passed directly must be excluded")

    def test_prod_sol_still_detected_alongside_test_files(self) -> None:
        """Both a production hit AND test files present - only production hit returned."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self._write(base, "src/Router.sol", VULNERABLE_UNOSWAP_CURFE)
            self._write(base, "test/Router.t.sol", VULNERABLE_UNOSWAP_CURFE)
            self._write(base, "script/Deploy.s.sol", VULNERABLE_UNOSWAP_CURFE)
            hits = MOD.scan_paths([base])
            self.assertEqual(len(hits), 1)
            self.assertIn("src/Router.sol", hits[0].path)


class LocalCorpusUnoswapCurveApproveMismatchDetectorTests(unittest.TestCase):
    def test_detects_unoswap_curfe_asm_approve_mismatch(self) -> None:
        hits = MOD.detect_source(VULNERABLE_UNOSWAP_CURFE, "UnoswapRouter.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].packet_id, "LCCR-PKT-013")
        self.assertEqual(hits[0].unoswap_function, "_unoswap")
        self.assertEqual(hits[0].curve_function, "_curfe")

    def test_detects_solidity_approve_pool_derived_token(self) -> None:
        hits = MOD.detect_source(VULNERABLE_SOLIDITY_APPROVE, "UnoswapRouter.sol")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].curve_function, "_curveSwap")

    def test_skips_when_unoswap_passes_declared_token_to_curve_helper(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_PASSES_TOKEN_TO_CURFE, "UnoswapRouter.sol"), [])

    def test_skips_when_curve_helper_approves_declared_or_trusted_token(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_APPROVES_DECLARED_TOKEN, "UnoswapRouter.sol"), [])

    def test_skips_without_router_pull_into_contract(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_NO_ROUTER_PULL, "UnoswapRouter.sol"), [])

    def test_cli_emits_packet_payload_and_nonzero_on_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "UnoswapRouter.sol"
            fixture.write_text(VULNERABLE_UNOSWAP_CURFE, encoding="utf-8")
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
            self.assertEqual(payload["selected_packet"], "LCCR-PKT-013")
            self.assertEqual(payload["hit_count"], 1)


if __name__ == "__main__":
    unittest.main()
