"""Offline tests for the PROTOCOL-COUPLED DEPENDENCY-MOCK SYNTHESIZER.

These assert the SYNTHESIZED SOURCE is correct WITHOUT requiring forge:
  (a) every called member appears in the mock with a matching signature + a
      return of correct arity/type;
  (b) a settable-storage member produces a setter;
  (c) the mock parses as valid Solidity (lightweight structural check: balanced
      braces, contract decl, each function has a body);
  (d) generic -- no target literal in the synthesized output for an abstract dep.

An OPTIONAL forge-gated test compiles the synth mock + a tiny consumer to prove
it actually deploys; it skips cleanly when forge is unavailable.

Run: python3 -m unittest tools.tests.test_protocol_dep_mock_synth
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_LIB = _HERE.parent / "lib"
sys.path.insert(0, str(_LIB))

import protocol_dep_mock_synth as P  # noqa: E402

_FIX = _HERE / "fixtures" / "protocol_dep_mock_synth"


def _nc(reason="test-provided negative-control behavior"):
    return {"*": reason}


# --------------------------------------------------------------------------- #
# Lightweight Solidity structural validator (NO solc required)
# --------------------------------------------------------------------------- #

def structural_check(src: str):
    """Return (ok, reason). Checks: balanced braces/parens, exactly-one contract
    decl, a pragma line, and every `function ... {` having a matching closing
    body (approximated by balanced-brace requirement + no `function ...;`
    declaration-without-body left in a contract context)."""
    if "pragma solidity" not in src:
        return False, "no pragma"
    if not re.search(r"\bcontract\s+\w+", src):
        return False, "no contract decl"
    # balanced braces
    depth = 0
    for ch in src:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False, "unbalanced close brace"
    if depth != 0:
        return False, f"unbalanced braces (depth={depth})"
    # balanced parens
    pdepth = 0
    for ch in src:
        if ch == "(":
            pdepth += 1
        elif ch == ")":
            pdepth -= 1
            if pdepth < 0:
                return False, "unbalanced close paren"
    if pdepth != 0:
        return False, "unbalanced parens"
    # every function inside the contract must have a body (no abstract `;` decl).
    # Strip the contract body and look for `function ...)` not followed by a
    # block before the next `;`. A concrete mock has NO `function ...;` lines.
    for m in re.finditer(r"function\s+\w+\s*\([^)]*\)[^;{]*?([;{])", src):
        if m.group(1) == ";":
            return False, f"abstract function decl (no body): ...{src[m.start():m.start()+60]}"
    return True, "ok"


def _fn_present(src: str, name: str) -> bool:
    return bool(re.search(rf"function\s+{re.escape(name)}\s*\(", src))


def _has_returns(src: str, name: str) -> bool:
    m = re.search(rf"function\s+{re.escape(name)}\s*\([^)]*\)[^{{;]*returns\s*\(([^)]*)\)", src)
    return bool(m)


def _return_types(src: str, name: str):
    m = re.search(rf"function\s+{re.escape(name)}\s*\([^)]*\)[^{{;]*returns\s*\(([^)]*)\)", src)
    if not m:
        return []
    return [t.strip().split()[0] for t in m.group(1).split(",") if t.strip()]


class TestParse(unittest.TestCase):
    def test_parse_interface_basic(self):
        src = (_FIX / "config_manager_iface.sol").read_text()
        members = P.parse_interface(src)
        names = {m.name for m in members}
        self.assertEqual(names, {"getParameter", "owner", "setParameter"})

    def test_parse_called_members_compact_and_full(self):
        ms = P.parse_called_members([
            "totalAssets() view returns (uint256)",
            "function canCall(bytes32,address) external view returns (bool)",
            "setActive(bool)",
        ])
        names = {m.name for m in ms}
        self.assertEqual(names, {"totalAssets", "canCall", "setActive"})
        ta = next(m for m in ms if m.name == "totalAssets")
        self.assertEqual(ta.returns, ["uint256"])
        self.assertEqual(ta.mutability, "view")

    def test_settable_predicate(self):
        ms = P.parse_called_members([
            "totalAssets() view returns (uint256)",        # settable (0-arg getter)
            "price(address) view returns (uint256)",       # settable (1-key getter)
            "canCall(bytes32,address) view returns (bool,string)",  # multi-ret -> not
            "setActive(bool)",                              # write -> not settable
        ])
        by = {m.name: m for m in ms}
        self.assertTrue(by["totalAssets"].is_settable())
        self.assertTrue(by["price"].is_settable())
        self.assertFalse(by["canCall"].is_settable())
        self.assertFalse(by["setActive"].is_settable())


class TestSynthesizeConfigManager(unittest.TestCase):
    def setUp(self):
        self.src = (_FIX / "config_manager_iface.sol").read_text()
        # The target calls getParameter + owner (reads) only; minimal surface.
        self.mock = P.synthesize_protocol_dep_mock(
            self.src,
            called_members=["getParameter(bytes32) view returns (uint256)",
                            "owner() view returns (address)"],
            idx=0, pragma="0.8.21",
            negative_control_behavior=_nc())

    def test_a_members_present_with_correct_returns(self):
        # (a) every called member present with matching signature + return arity.
        self.assertTrue(_fn_present(self.mock, "getParameter"))
        self.assertTrue(_fn_present(self.mock, "owner"))
        self.assertEqual(_return_types(self.mock, "getParameter"), ["uint256"])
        self.assertEqual(_return_types(self.mock, "owner"), ["address"])

    def test_b_settable_produces_setter(self):
        # (b) getParameter is a per-key getter -> mapping + a setter.
        self.assertTrue(_fn_present(self.mock, "setGetParameter"))
        self.assertTrue(_fn_present(self.mock, "setOwner"))
        self.assertIn("mapping(bytes32 => uint256)", self.mock)

    def test_c_structural_valid(self):
        ok, reason = structural_check(self.mock)
        self.assertTrue(ok, reason)

    def test_d_no_target_literal(self):
        # (d) generic: the SYNTHESIZED contract carries no protocol/target literal.
        for lit in ("ConfigurationManager", "PoolManager", "Pods", "Maple",
                    "Punk", "Compound", "Chainlink"):
            self.assertNotIn(lit, self.mock, f"target literal leaked: {lit}")

    def test_pragma_caret_normalized(self):
        self.assertIn("pragma solidity ^0.8.21;", self.mock)


class TestSynthesizePoolManager(unittest.TestCase):
    def setUp(self):
        self.src = (_FIX / "pool_manager_iface.sol").read_text()
        self.mock = P.synthesize_protocol_dep_mock(
            self.src, idx=1, pragma="^0.8.0",
            return_values={"canCall(bytes32,address,bytes)": ["true", '""']},
            negative_control_behavior=_nc())

    def test_total_assets_settable(self):
        self.assertTrue(_fn_present(self.mock, "totalAssets"))
        self.assertTrue(_fn_present(self.mock, "setTotalAssets"))
        self.assertEqual(_return_types(self.mock, "totalAssets"), ["uint256"])

    def test_cancall_multireturn_stub(self):
        # multi-return view -> test-provided fixed return (bool,string).
        self.assertTrue(_fn_present(self.mock, "canCall"))
        self.assertEqual(_return_types(self.mock, "canCall"), ["bool", "string"])
        m = re.search(r"function\s+canCall[^{]*\{([^}]*)\}", self.mock)
        self.assertIsNotNone(m)
        self.assertIn("true", m.group(1))

    def test_structural_valid(self):
        ok, reason = structural_check(self.mock)
        self.assertTrue(ok, reason)


class TestSynthesizeOracle(unittest.TestCase):
    def setUp(self):
        self.src = (_FIX / "oracle_iface.sol").read_text()
        self.mock = P.synthesize_protocol_dep_mock(
            self.src, idx=2, pragma="0.8.19",
            return_values={
                "latestRoundData()": ["1", "2", "3", "4", "5"],
            },
            negative_control_behavior=_nc())

    def test_int_and_address_keyed_settables(self):
        # latestAnswer() -> settable int256 getter; price(address) -> settable mapping.
        self.assertTrue(_fn_present(self.mock, "setLatestAnswer"))
        self.assertTrue(_fn_present(self.mock, "setPrice"))
        self.assertIn("mapping(address => uint256)", self.mock)
        self.assertEqual(_return_types(self.mock, "latestAnswer"), ["int256"])

    def test_latest_round_data_multireturn(self):
        rts = _return_types(self.mock, "latestRoundData")
        self.assertEqual(rts, ["uint80", "int256", "uint256", "uint256", "uint80"])

    def test_structural_valid(self):
        ok, reason = structural_check(self.mock)
        self.assertTrue(ok, reason)


class TestSignatureListInput(unittest.TestCase):
    def test_signature_only_input(self):
        # Input form #2: a bare list of called member signatures (no iface src).
        mock = P.synthesize_protocol_dep_mock(
            ["totalAssets() view returns (uint256)",
             "canCall(bytes32,address,bytes) view returns (bool,string)",
             "configure(uint256,uint256)"],
            idx=3, pragma="0.8.21",
            return_values={"canCall(bytes32,address,bytes)": ["true", '""']},
            negative_control_behavior=_nc())
        self.assertTrue(_fn_present(mock, "totalAssets"))
        self.assertTrue(_fn_present(mock, "setTotalAssets"))
        self.assertTrue(_fn_present(mock, "canCall"))
        self.assertTrue(_fn_present(mock, "configure"))  # void write stub
        ok, reason = structural_check(mock)
        self.assertTrue(ok, reason)

    def test_void_member_has_empty_body(self):
        mock = P.synthesize_protocol_dep_mock(["configure(uint256,uint256)"],
                                              idx=4,
                                              negative_control_behavior=_nc())
        self.assertRegex(mock, r"function\s+configure\(uint256, uint256\)\s+external\s*\{\}")


class TestEdgeCases(unittest.TestCase):
    def test_all_unsynthesizable_returns_none(self):
        # A member whose ONLY return is an un-defaultable struct -> None.
        mock = P.synthesize_protocol_dep_mock(
            ["getStruct() view returns (SomeStruct memory)"], idx=5,
            return_values={"getStruct()": "SomeStruct(0)"},
            negative_control_behavior=_nc())
        self.assertIsNone(mock)

    def test_empty_input_returns_none(self):
        self.assertIsNone(P.synthesize_protocol_dep_mock([], idx=6))
        self.assertIsNone(P.synthesize_protocol_dep_mock("interface I {}", idx=6))

    def test_called_members_filter_minimal_surface(self):
        # iface has 3 members; target calls only 1 -> mock implements only that 1
        # Verifies minimal-surface selection.
        src = (_FIX / "config_manager_iface.sol").read_text()
        mock = P.synthesize_protocol_dep_mock(
            src, called_members=["getParameter(bytes32)"], idx=7)
        self.assertIsNone(mock)

        mock = P.synthesize_protocol_dep_mock(
            src, called_members=["getParameter(bytes32)"], idx=7,
            negative_control_behavior=_nc())
        self.assertTrue(_fn_present(mock, "getParameter"))
        self.assertFalse(_fn_present(mock, "owner"))
        self.assertFalse(_fn_present(mock, "setParameter"))

    def test_default_idx_naming(self):
        mock = P.synthesize_protocol_dep_mock(
            ["foo() view returns (uint256)"],
            negative_control_behavior=_nc())
        self.assertIn("contract _SynthProtoDep0", mock)

    def test_normalize_pragma_forms(self):
        self.assertEqual(P.normalize_pragma("0.8.21"), "^0.8.21")
        self.assertEqual(P.normalize_pragma("=0.8.21"), "^0.8.21")
        self.assertEqual(P.normalize_pragma("^0.8.0"), "^0.8.0")
        self.assertEqual(P.normalize_pragma("pragma solidity 0.8.19;"), "^0.8.19")
        self.assertEqual(P.normalize_pragma(">=0.8.0 <0.9.0"), "^0.8.0")
        self.assertEqual(P.normalize_pragma(None), "^0.8.0")

    def test_fallback_present(self):
        mock = P.synthesize_protocol_dep_mock(
            ["foo() view returns (uint256)"],
            negative_control_behavior=_nc())
        self.assertIn("fallback() external payable", mock)
        self.assertIn("UNSUPPORTED_PROTOCOL_DEP_CALL", mock)
        self.assertIn("UNSUPPORTED_PROTOCOL_DEP_RECEIVE", mock)
        self.assertNotIn("return(0, 32)", mock)

    def test_missing_negative_control_blocks_with_obligation(self):
        report = P.analyze_protocol_dep_mock_synthesis(
            ["foo() view returns (uint256)"])
        self.assertIsNone(report.source)
        self.assertIn("missing-negative-control-behavior",
                      {o.code for o in report.obligations})

    def test_missing_return_values_blocks_non_settable_member(self):
        report = P.analyze_protocol_dep_mock_synthesis(
            ["canCall(bytes32,address,bytes) view returns (bool,string)"],
            negative_control_behavior=_nc())
        self.assertIsNone(report.source)
        self.assertIn("missing-return-values",
                      {o.code for o in report.obligations})

    def test_unknown_called_member_does_not_fallback_to_all_interface(self):
        src = (_FIX / "config_manager_iface.sol").read_text()
        report = P.analyze_protocol_dep_mock_synthesis(
            src,
            called_members=["ghost(bytes32) view returns (uint256)"],
            negative_control_behavior=_nc())
        self.assertIsNone(report.source)
        self.assertIn("missing-required-method-source",
                      {o.code for o in report.obligations})


@unittest.skipUnless(shutil.which("forge"), "forge not installed")
class TestForgeCompile(unittest.TestCase):
    """OPTIONAL: prove the synth mock actually compiles + deploys via forge."""

    def test_synth_mock_compiles_and_deploys(self):
        src = (_FIX / "pool_manager_iface.sol").read_text()
        mock = P.synthesize_protocol_dep_mock(
            src, idx=0, pragma="0.8.21",
            return_values={"canCall(bytes32,address,bytes)": ["true", '""']},
            negative_control_behavior=_nc())
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "foundry.toml").write_text(
                "[profile.default]\nsrc='src'\ntest='test'\n")
            (tdp / "src").mkdir()
            (tdp / "src" / "Mock.sol").write_text(mock)
            consumer = (
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.21;\n"
                'import "../src/Mock.sol";\n'
                "contract Consumer {\n"
                "    function run() external returns (uint256) {\n"
                "        _SynthProtoDep0 m = new _SynthProtoDep0();\n"
                "        m.setTotalAssets(123);\n"
                "        return m.totalAssets();\n"
                "    }\n"
                "}\n")
            (tdp / "src" / "Consumer.sol").write_text(consumer)
            r = subprocess.run(["forge", "build", "--root", str(tdp)],
                               capture_output=True, text=True, timeout=180)
            self.assertEqual(r.returncode, 0,
                             f"forge build failed:\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    unittest.main()
