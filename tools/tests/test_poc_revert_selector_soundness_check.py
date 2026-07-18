from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "poc-revert-selector-soundness-check.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("poc_revert_selector_soundness_check", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def _write(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# ------------------------------------------------------------------ scaffolds

_INSCOPE_ERRORS = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
interface IErrors {
    error MinSharesViolation();
    error Unauthorized();
}
"""

_OOS_MOCK_ETHENA = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
// OOS mock - identical error name, different threshold.
interface IStakedUSDe {
    error MinSharesViolation();
}
"""

_OOS_MOCK_NEUTRL = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
contract sNUSD {
    error MinSharesViolation();
}
"""


def _poc(expect_lines: str) -> str:
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.28;\n"
        "import {Test} from \"forge-std/Test.sol\";\n"
        "interface IErr { error MinSharesViolation(); }\n"
        "contract PoC is Test {\n"
        "    function test_x() public {\n"
        f"{expect_lines}\n"
        "    }\n"
        "}\n"
    )


class PocRevertSelectorSoundnessTest(unittest.TestCase):
    # (a) dual-declared custom error + selector-only expectRevert -> FLAG.
    def test_a_dual_declared_selector_only_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "foundry.toml", "[profile.default]\nsrc = 'src'\n")
            _write(root, "src/interfaces/IErrors.sol", _INSCOPE_ERRORS)
            _write(root, "src/test/ethena/IStakedUSDe.sol", _OOS_MOCK_ETHENA)
            poc = _write(root, "src/test/FreezePoC.t.sol",
                         _poc("        vm.expectRevert(IErr.MinSharesViolation.selector);\n"
                              "        target.redeem();"))
            decls = MOD._scan_declarations(str(root))
            results = MOD.check_poc_file(str(poc), decls)
            custom = [r for r in results if r["kind"] == "custom"]
            self.assertEqual(len(custom), 1)
            self.assertEqual(custom[0]["verdict"], "fail-ambiguous")
            self.assertEqual(custom[0]["error_name"], "MinSharesViolation")
            self.assertTrue(custom[0]["ambiguity"]["cross_scope"])
            self.assertTrue(custom[0]["ambiguity"]["has_oos_declaration"])
            self.assertTrue(custom[0]["ambiguity"]["has_inscope_declaration"])
            # full main() exits 1.
            rc = MOD.main([str(poc), "--src-root", str(root)])
            self.assertEqual(rc, 1)

    # (a2) three declaring sites (strata shape) -> FLAG with 3 distinct files.
    def test_a2_three_declaring_sites_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "src/interfaces/IErrors.sol", _INSCOPE_ERRORS)
            _write(root, "src/test/ethena/IStakedUSDe.sol", _OOS_MOCK_ETHENA)
            _write(root, "src/test/neutrl/sNUSD.sol", _OOS_MOCK_NEUTRL)
            poc = _write(root, "src/test/FreezePoC.t.sol",
                         _poc("        vm.expectRevert(IErr.MinSharesViolation.selector);"))
            decls = MOD._scan_declarations(str(root))
            results = MOD.check_poc_file(str(poc), decls)
            custom = [r for r in results if r["kind"] == "custom"]
            self.assertEqual(custom[0]["verdict"], "fail-ambiguous")
            # PoC's own IErr + IErrors + 2 OOS mocks = 4 distinct declaring files.
            self.assertGreaterEqual(len(custom[0]["ambiguity"]["distinct_files"]), 3)

    # (b) uniquely-declared error -> PASS.
    def test_b_unique_declaration_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "src/interfaces/IErrors.sol",
                   "pragma solidity 0.8.28;\ninterface IErrors { error UniqueGuardError(); }\n")
            poc = _write(root, "src/test/UniquePoC.t.sol",
                         "pragma solidity 0.8.28;\n"
                         "import {IErrors} from \"../interfaces/IErrors.sol\";\n"
                         "contract PoC {\n"
                         "  function t() public {\n"
                         "    vm.expectRevert(IErrors.UniqueGuardError.selector);\n"
                         "  }\n"
                         "}\n")
            decls = MOD._scan_declarations(str(root))
            results = MOD.check_poc_file(str(poc), decls)
            custom = [r for r in results if r["kind"] == "custom"]
            self.assertEqual(len(custom), 1)
            self.assertEqual(custom[0]["verdict"], "pass-unique")
            rc = MOD.main([str(poc), "--src-root", str(root)])
            self.assertEqual(rc, 0)

    # (c) address-pinned expectRevert (2-arg overload) -> PASS even if multi-declared.
    def test_c_address_pinned_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "src/interfaces/IErrors.sol", _INSCOPE_ERRORS)
            _write(root, "src/test/ethena/IStakedUSDe.sol", _OOS_MOCK_ETHENA)
            poc = _write(root, "src/test/PinnedPoC.t.sol",
                         _poc("        vm.expectRevert(IErr.MinSharesViolation.selector, address(jrtVault));"))
            decls = MOD._scan_declarations(str(root))
            results = MOD.check_poc_file(str(poc), decls)
            custom = [r for r in results if r["kind"] == "custom"]
            self.assertEqual(len(custom), 1)
            self.assertTrue(custom[0]["address_pinned"])
            self.assertEqual(custom[0]["verdict"], "pass-pinned")
            rc = MOD.main([str(poc), "--src-root", str(root)])
            self.assertEqual(rc, 0)

    # (d) string revert -> NA (never flagged, exit 0).
    def test_d_string_revert_is_na(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "src/interfaces/IErrors.sol", _INSCOPE_ERRORS)
            _write(root, "src/test/ethena/IStakedUSDe.sol", _OOS_MOCK_ETHENA)
            poc = _write(root, "src/test/StringPoC.t.sol",
                         _poc('        vm.expectRevert("MIN_SHARES");'))
            decls = MOD._scan_declarations(str(root))
            results = MOD.check_poc_file(str(poc), decls)
            # No custom-error results; the string one is NA.
            custom = [r for r in results if r["kind"] == "custom"]
            self.assertEqual(len(custom), 0)
            na = [r for r in results if r["verdict"] == "na"]
            self.assertGreaterEqual(len(na), 1)
            rc = MOD.main([str(poc), "--src-root", str(root)])
            self.assertEqual(rc, 0)

    # (e) abi.encodeWithSelector(X.selector, ...) form is resolved and flagged.
    def test_e_encode_with_selector_form_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "src/interfaces/IErrors.sol", _INSCOPE_ERRORS)
            _write(root, "src/test/ethena/IStakedUSDe.sol", _OOS_MOCK_ETHENA)
            poc = _write(root, "src/test/EncodePoC.t.sol",
                         _poc("        vm.expectRevert(abi.encodeWithSelector(IErr.MinSharesViolation.selector));"))
            decls = MOD._scan_declarations(str(root))
            results = MOD.check_poc_file(str(poc), decls)
            custom = [r for r in results if r["kind"] == "custom"]
            self.assertEqual(len(custom), 1)
            self.assertEqual(custom[0]["error_name"], "MinSharesViolation")
            self.assertEqual(custom[0]["verdict"], "fail-ambiguous")

    # (f) no-arg expectRevert() -> NA.
    def test_f_no_arg_expect_is_na(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "foundry.toml", "[profile.default]\n")
            _write(root, "src/interfaces/IErrors.sol", _INSCOPE_ERRORS)
            poc = _write(root, "src/test/NoArgPoC.t.sol",
                         _poc("        vm.expectRevert();"))
            decls = MOD._scan_declarations(str(root))
            results = MOD.check_poc_file(str(poc), decls)
            custom = [r for r in results if r["kind"] == "custom"]
            self.assertEqual(len(custom), 0)
            rc = MOD.main([str(poc), "--src-root", str(root)])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
