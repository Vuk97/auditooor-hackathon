"""Lane F (SEI 2026-07-05): hunt-coverage-gate exempts bodyless Solidity
interface/abstract declarations from queued_not_scanned.

A Cosmos-EVM L1 (SEI) ships ``precompiles/<mod>/<Mod>.sol`` ABI mirrors that are pure
``interface`` declarations (0 function bodies) of the Go precompile implementation. The
Go impl carries the real hunt obligation; the bodyless mirror decls have nothing to scan
and lingered forever as queued_not_scanned (830 ``Bank.sol::send`` etc.) -> permanent
false-red. This exemption removes ONLY positively-bodyless Solidity declarations; any
function with an implementation body keeps its obligation (never-false-pass).
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "hcg", str(Path(__file__).resolve().parents[1] / "hunt-coverage-gate.py")
)
hcg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hcg)


class SolInterfaceExemptTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "Bank.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "interface IBank {\n"
            "  function send(address a, uint256 x) external returns (bool);\n"
            "  function balance(address a) external view returns (uint256);\n"
            "}\n"
        )
        (self.d / "Impl.sol").write_text(
            "contract Impl {\n"
            "  function send(address a) public returns (bool) { return true; }\n"
            "}\n"
        )
        (self.d / "Mix.sol").write_text(
            "abstract contract M {\n"
            "  function f() external virtual returns (bool);\n"
            "  function g() public returns (bool) { return false; }\n"
            "}\n"
        )

    def _f(self, unit):
        return hcg._unit_is_solidity_interface_decl(self.d, unit)

    def test_interface_method_bodyless_is_exempt(self):
        self.assertTrue(self._f("Bank.sol::send"))
        self.assertTrue(self._f("Bank.sol::balance"))

    def test_implemented_contract_function_NOT_exempt(self):
        # never-false-pass: real logic keeps its hunt obligation
        self.assertFalse(self._f("Impl.sol::send"))

    def test_abstract_bodyless_exempt_but_implemented_sibling_NOT(self):
        self.assertTrue(self._f("Mix.sol::f"))      # bodyless -> exempt
        self.assertFalse(self._f("Mix.sol::g"))     # implemented -> obligated

    def test_nonexistent_fn_not_exempt(self):
        self.assertFalse(self._f("Bank.sol::doesNotExist"))

    def test_non_solidity_unit_not_exempt(self):
        self.assertFalse(self._f("keeper.go::SetBalance"))
        self.assertFalse(self._f("lib.rs::transfer"))

    def test_file_only_unit_not_exempt_here(self):
        # file-only (no ::) has its own exemption path; this helper stays out
        self.assertFalse(self._f("Bank.sol"))


if __name__ == "__main__":
    unittest.main()
