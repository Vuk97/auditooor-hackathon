#!/usr/bin/env python3
"""Regression tests for mock-reference-divergence-check.py.

Strata 2026-07-07: a lane rolled its own `contract MockDepositVault is
IDepositVault` (pulling the raw 18-dec amount) while the workspace shipped
test/midas/MockDepositVault.sol (converting base18->native), producing a
false-positive Medium after a 1.2M-call campaign. This gate flags a harness that
re-implements a mock of a protocol-specific dependency the workspace already
ships a reference for."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location(
    "mrd", _H.parent / "mock-reference-divergence-check.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


def _ws():
    return Path(tempfile.mkdtemp())


def _write(ws, rel, body):
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


_REF = ("// ref\ncontract MockDepositVault is IDepositVault {\n"
        "  function depositInstant(address t, uint256 a18, uint256, bytes32) external {\n"
        "    uint256 amt = a18 / (10 ** (18 - 6));\n"
        "    IERC20(t).transferFrom(msg.sender, address(this), amt);\n  }\n}\n")


class T(unittest.TestCase):
    def test_flags_rolled_own_protocol_mock(self):
        ws = _ws()
        _write(ws, "src/contracts/test/midas/MockDepositVault.sol", _REF)
        _write(ws, "chimera_harnesses/H/H.sol",
               "contract MockDepositVault is IDepositVault {\n"
               "  function depositInstant(address t, uint256 a18, uint256, bytes32) external {\n"
               "    IERC20(t).transferFrom(msg.sender, address(this), a18);\n  }\n}\n")
        r = m.check(ws)
        risks = [f for f in r["findings"] if f["status"] == "divergence-risk"]
        self.assertEqual(len(risks), 1, r["findings"])
        self.assertEqual(risks[0]["harness_mock"], "MockDepositVault")
        self.assertIn("MockDepositVault.sol", risks[0]["reference_file"])

    def test_import_of_reference_is_not_flagged(self):
        ws = _ws()
        _write(ws, "src/contracts/test/midas/MockDepositVault.sol", _REF)
        _write(ws, "chimera_harnesses/H/H.sol",
               "import {MockDepositVault} from '../../src/contracts/test/midas/MockDepositVault.sol';\n"
               "contract Harness { }\n")
        self.assertEqual(m.check(ws)["divergence_risks"], 0)

    def test_standard_erc20_mock_not_flagged(self):
        ws = _ws()
        _write(ws, "src/contracts/test/MockERC20.sol", "contract MockERC20 is IERC20 {}\n")
        _write(ws, "chimera_harnesses/H/H.sol", "contract MockERC20 is IERC20 {}\n")
        self.assertEqual(m.check(ws)["divergence_risks"], 0)

    def test_our_own_poc_is_not_a_reference(self):
        # a mock defined only in ANOTHER of our audit PoCs is not ground truth.
        ws = _ws()
        _write(ws, "submissions/staging/x/x_PoC.sol",
               "contract MockDepositVault is IDepositVault {}\n")
        _write(ws, "chimera_harnesses/H/H.sol",
               "contract MockDepositVault is IDepositVault {}\n")
        self.assertEqual(m.check(ws)["divergence_risks"], 0)

    def test_no_reference_no_flag(self):
        ws = _ws()
        _write(ws, "chimera_harnesses/H/H.sol",
               "contract MockDepositVault is IDepositVault {}\n")
        self.assertEqual(m.check(ws)["divergence_risks"], 0)

    def test_rebuttal_clears(self):
        ws = _ws()
        _write(ws, "src/contracts/test/midas/MockDepositVault.sol", _REF)
        _write(ws, "chimera_harnesses/H/H.sol",
               "// <!-- mock-reference-divergence-rebuttal: reference is abstract -->\n"
               "contract MockDepositVault is IDepositVault {}\n")
        r = m.check(ws)
        self.assertEqual(r["divergence_risks"], 0)
        self.assertTrue(any(f["status"] == "rebutted" for f in r["findings"]))

    def test_strict_fails(self):
        ws = _ws()
        _write(ws, "src/contracts/test/midas/MockDepositVault.sol", _REF)
        _write(ws, "chimera_harnesses/H/H.sol",
               "contract MockDepositVault is IDepositVault {}\n")
        os.environ["AUDITOOOR_MOCK_REFERENCE_STRICT"] = "1"
        try:
            self.assertEqual(m.check(ws)["verdict"], "fail-mock-reference-divergence")
        finally:
            del os.environ["AUDITOOOR_MOCK_REFERENCE_STRICT"]


if __name__ == "__main__":
    unittest.main()
