#!/usr/bin/env python3
"""Regression: body-less Solidity interface files are exempt from the coverage
denominator (axelar-sc: 277 of 293 uncovered were contracts/interfaces/I*.sol -
permanently uncoverable, inflating the swept-surface coverage-map to a false FAIL)."""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "workspace-coverage-heatmap.py"


def _load():
    spec = importlib.util.spec_from_file_location("wch", _TOOL)
    m = importlib.util.module_from_spec(spec); sys.modules["wch"] = m
    spec.loader.exec_module(m); return m


wch = _load()


class TestInterfaceOnlyExempt(unittest.TestCase):
    def _write(self, name, body):
        d = Path(tempfile.mkdtemp())
        p = d / name; p.write_text(body); return str(p)

    def test_pure_interface_is_exempt(self):
        f = self._write("IFoo.sol",
            "pragma solidity ^0.8.0;\ninterface IFoo {\n  function bar(uint256 x) external returns (uint256);\n  function baz() external view returns (address);\n}\n")
        self.assertTrue(wch._is_interface_only_sol_file(f))

    def test_contract_impl_is_kept(self):
        f = self._write("Foo.sol",
            "pragma solidity ^0.8.0;\ncontract Foo {\n  function bar(uint256 x) external returns (uint256) { return x + 1; }\n}\n")
        self.assertFalse(wch._is_interface_only_sol_file(f))

    def test_library_is_kept(self):
        f = self._write("AddressBytes.sol",
            "pragma solidity ^0.8.0;\nlibrary AddressBytes {\n  function toAddress(bytes memory b) internal pure returns (address a) { assembly { a := mload(add(b,20)) } }\n}\n")
        self.assertFalse(wch._is_interface_only_sol_file(f))

    def test_mixed_interface_plus_contract_is_kept(self):
        f = self._write("Mixed.sol",
            "interface IX { function a() external; }\ncontract X is IX {\n  function a() external override {}\n}\n")
        self.assertFalse(wch._is_interface_only_sol_file(f))

    def test_interface_name_in_comment_not_impl(self):
        # a `contract`/`library` word ONLY inside a comment must not keep the file
        f = self._write("IBar.sol",
            "// this interface replaces the old contract Bar\n/* library-style helpers */\ninterface IBar { function q() external view returns (uint256); }\n")
        self.assertTrue(wch._is_interface_only_sol_file(f))


if __name__ == "__main__":
    unittest.main()
