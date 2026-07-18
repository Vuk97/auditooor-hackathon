from __future__ import annotations

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "klbq006-terminal-boundary.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("klbq006_terminal_boundary", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


class Klbq006TerminalBoundaryTest(unittest.TestCase):
    def test_solidity_only_root_makes_rust_detector_absence_terminal_inapplicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "policies" / "Guard.sol"
            src.parent.mkdir(parents=True)
            src.write_text("contract Guard { function checkTransaction() external {} }\n", encoding="utf-8")

            report = MOD.build_report(renft_root=root, pinned_ref="WORKTREE", head_ref="WORKTREE")

        boundary = report["rust_detector_boundary"]
        self.assertEqual(boundary["state"], "terminal_inapplicable")
        self.assertEqual(boundary["reason"], "source_language_mismatch_solidity_root_without_rust_files")
        self.assertFalse(boundary["can_interpret_detector_absence_as_clean_result"])
        self.assertIn("not a pass", boundary["absence_interpretation"])
        self.assertFalse(report["verification_claim_allowed"])
        self.assertFalse(report["promotion_ready"])

    def test_rust_source_present_is_not_the_solidity_terminal_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "contracts" / "klbq006" / "src" / "lib.rs"
            src.parent.mkdir(parents=True)
            src.write_text("pub fn check_transaction() {}\n", encoding="utf-8")

            report = MOD.build_report(renft_root=root, pinned_ref="WORKTREE", head_ref="WORKTREE")

        self.assertEqual(report["rust_detector_boundary"]["state"], "rust_source_present_not_terminal")
        self.assertFalse(report["rust_detector_boundary"]["can_interpret_detector_absence_as_clean_result"])

    def test_source_probe_records_missing_direct_setfallbackhandler_guard_without_closure(self) -> None:
        texts = {
            "src/policies/Guard.sol": "\n".join(
                [
                    "contract Guard {",
                    "  function _checkTransaction(address from, address to, bytes memory data) private view {",
                    "    bytes4 selector;",
                    "    if (selector == gnosis_safe_set_guard_selector) {",
                    "      revert Errors.GuardPolicy_UnauthorizedSelector(selector);",
                    "    }",
                    "  }",
                    "  function checkTransaction() external {}",
                    "}",
                ]
            ),
            "src/policies/Factory.sol": "contract Factory { address fallbackHandler; function setup() external {} }\n",
            "src/libraries/RentalConstants.sol": "bytes4 constant gnosis_safe_set_guard_selector = 0xe19a9dd9;\n",
        }

        probe = MOD.probe_solidity_texts(texts, ref="fixture", commit="abc")

        self.assertEqual(
            probe["classification"],
            "source_aware_guard_boundary_missing_direct_setfallbackhandler_revert",
        )
        self.assertFalse(probe["signals"]["guard_reverts_setfallbackhandler_selector"])
        self.assertFalse(probe["claim_limits"]["verification_claim_allowed"])
        self.assertFalse(probe["claim_limits"]["exploit_proof_allowed"])

    def test_source_probe_records_fixed_guard_anchor_but_still_not_exploit_proof(self) -> None:
        texts = {
            "src/policies/Guard.sol": "\n".join(
                [
                    "contract Guard {",
                    "  function _checkTransaction(address from, address to, bytes memory data) private view {",
                    "    bytes4 selector;",
                    "    if (selector == gnosis_safe_set_fallback_handler_selector) {",
                    "      revert Errors.GuardPolicy_UnauthorizedSelector(gnosis_safe_set_fallback_handler_selector);",
                    "    }",
                    "  }",
                    "  function checkTransaction() external {}",
                    "}",
                ]
            ),
            "src/policies/Factory.sol": "contract Factory { address fallbackHandler; function setup() external {} }\n",
            "src/libraries/RentalConstants.sol": (
                "bytes4 constant gnosis_safe_set_fallback_handler_selector = 0xf08a0323;\n"
            ),
            "test/unit/Guard/CheckTransaction.t.sol": "\n".join(
                [
                    "function test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler() public {",
                    "  vm.expectRevert();",
                    "  gnosis_safe_set_fallback_handler_selector;",
                    "}",
                ]
            ),
        }

        probe = MOD.probe_solidity_texts(texts, ref="fixture", commit="def")

        self.assertEqual(
            probe["classification"],
            "source_aware_guard_rejects_setfallbackhandler_with_test_anchor",
        )
        self.assertTrue(probe["signals"]["guard_reverts_setfallbackhandler_selector"])
        self.assertTrue(probe["signals"]["test_covers_setfallbackhandler_revert"])
        self.assertFalse(probe["claim_limits"]["executable_solidity_replay_performed"])
        self.assertFalse(probe["claim_limits"]["exploit_proof_allowed"])

    def test_taxonomy_packet_keeps_input_validation_as_parent_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "policies" / "Guard.sol"
            src.parent.mkdir(parents=True)
            src.write_text("contract Guard { function checkTransaction() external {} }\n", encoding="utf-8")

            report = MOD.build_report(renft_root=root, pinned_ref="WORKTREE", head_ref="WORKTREE")

        taxonomy = report["taxonomy_reconciliation"]
        self.assertEqual(
            taxonomy["canonical_leaf_family"],
            "safe-fallback-handler-setter-missing-address-guard",
        )
        self.assertEqual(taxonomy["parent_class"], "input-validation")
        self.assertEqual(taxonomy["input_validation_usage"], "parent_or_alias_only")
        self.assertFalse(taxonomy["repo_wide_metadata_updated"])
        self.assertEqual(taxonomy["closure_posture"], "open")


if __name__ == "__main__":
    unittest.main()
