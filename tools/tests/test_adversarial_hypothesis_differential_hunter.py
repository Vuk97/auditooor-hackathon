#!/usr/bin/env python3
# r36-rebuttal: bugfix-inventory-claude-20260610
"""Tests for tools/adversarial-hypothesis-differential-hunter.py."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "adversarial-hypothesis-differential-hunter.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("ahdh", TOOL)
    assert spec and spec.loader, "adversarial-hypothesis-differential-hunter.py missing"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ahdh"] = mod
    spec.loader.exec_module(mod)
    return mod


AHDH = _load_tool()


SIMPLE_VAULT = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract Vault {
        mapping(address => uint256) public balanceOf;
        uint256 public totalSupply;

        function deposit() external payable {
            balanceOf[msg.sender] += msg.value;
            totalSupply += msg.value;
        }

        function withdraw(uint256 amount) external {
            require(balanceOf[msg.sender] >= amount, "balance");
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok, "send");
            balanceOf[msg.sender] -= amount;
            totalSupply -= amount;
        }

        function previewRedeem(uint256 shares) external view returns (uint256) {
            return shares * address(this).balance / totalSupply;
        }
    }
    """
)


class AdversarialHypothesisDifferentialHunterTests(unittest.TestCase):
    def test_simple_solidity_parsing_extracts_functions_and_state_writes(self) -> None:
        records = AHDH.parse_solidity_source(SIMPLE_VAULT, "Vault.sol")
        by_name = {record.function_name: record for record in records}

        self.assertIn("deposit", by_name)
        self.assertIn("withdraw", by_name)
        self.assertIn("previewRedeem", by_name)
        self.assertEqual(by_name["withdraw"].visibility, "external")
        self.assertEqual(by_name["previewRedeem"].state_mutability, "view")
        self.assertIn("balanceOf", by_name["withdraw"].state_vars)
        self.assertIn("totalSupply", by_name["withdraw"].state_writes)
        self.assertTrue(by_name["withdraw"].external_calls)

    def test_ranking_prioritizes_reentrancy_differential_for_external_call_before_state_write(self) -> None:
        withdraw = next(
            record
            for record in AHDH.parse_solidity_source(SIMPLE_VAULT, "Vault.sol")
            if record.function_name == "withdraw"
        )

        hypotheses = AHDH.build_hypotheses_for_function(withdraw, max_hypotheses=3)

        self.assertGreaterEqual(len(hypotheses), 1)
        self.assertEqual(hypotheses[0]["attack_class"], "reentrancy-state-differential")
        self.assertGreater(hypotheses[0]["score"], 80)
        self.assertIn("attacker_goal", hypotheses[0])
        self.assertIn("differentiator_against_normal_path", hypotheses[0])
        self.assertIn("balanceOf", hypotheses[0]["manipulated_state"])

    def test_foundry_skeleton_contains_differential_shape_and_target_selector(self) -> None:
        source = textwrap.dedent(
            """\
            pragma solidity ^0.8.20;
            contract Sweeper {
                function sweep(address token, uint256 amount) external {
                    (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount));
                    require(ok);
                }
            }
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "Sweeper.sol"
            sol.write_text(source, encoding="utf-8")

            payload = AHDH.build_payload([sol], emit_foundry_skeleton=True, max_hypotheses_per_function=2)

        skeletons = [
            hyp["foundry_test_skeleton"]
            for hyp in payload["hypotheses"]
            if "foundry_test_skeleton" in hyp
        ]
        self.assertTrue(skeletons)
        skeleton = skeletons[0]
        self.assertIn('import "forge-std/Test.sol";', skeleton)
        self.assertIn("vm.startPrank(attacker);", skeleton)
        self.assertIn('abi.encodeWithSignature("sweep(address,uint256)"', skeleton)
        self.assertIn("Differential assertion", skeleton)

    def test_json_manifest_input_generates_function_hypotheses(self) -> None:
        manifest = {
            "functions": [
                {
                    "file_path": "Router.sol",
                    "contract_name": "Router",
                    "function_name": "execute",
                    "function_signature": "function execute(address target, bytes calldata data) external",
                    "visibility": "external",
                    "state_mutability": "nonpayable",
                    "params": [
                        {"name": "target", "type": "address"},
                        {"name": "data", "type": "bytes calldata"},
                    ],
                    "body": "{ (bool ok, ) = target.call(data); require(ok); }",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "functions.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            payload = AHDH.build_payload([], manifest_path=manifest_path, max_hypotheses_per_function=4)

        self.assertEqual(payload["summary"]["function_count"], 1)
        classes = {hyp["attack_class"] for hyp in payload["hypotheses"]}
        self.assertIn("arbitrary-call-surface", classes)

    def test_iter_solidity_sources_skips_certora_and_test_dirs(self) -> None:
        """Files under certora/ or test/ directories must be excluded; production files kept."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # production file - should be included
            (root / "src" / "core").mkdir(parents=True)
            (root / "src" / "core" / "Morpho.sol").write_text("contract Morpho {}")
            # certora harness - must be excluded
            (root / "src" / "certora" / "helpers").mkdir(parents=True)
            (root / "src" / "certora" / "helpers" / "MorphoHarness.sol").write_text(
                "contract MorphoHarness {}"
            )
            # test file in test/ dir - must be excluded (even without .t.sol suffix)
            (root / "src" / "test").mkdir(parents=True)
            (root / "src" / "test" / "Morpho.t.sol").write_text("contract MorphoTest {}")
            # mock file - must be excluded
            (root / "src" / "mocks").mkdir(parents=True)
            (root / "src" / "mocks" / "MockToken.sol").write_text("contract MockToken {}")

            warnings: list[str] = []
            result = AHDH._iter_solidity_sources([root / "src"], warnings)
            names = [p.name for p in result]

        self.assertEqual(
            names,
            ["Morpho.sol"],
            f"expected only Morpho.sol but got {names}",
        )

    def test_iter_solidity_sources_skips_halmos_kontrol_spec(self) -> None:
        """halmos/, kontrol/, spec/, specs/ directories must also be excluded."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Real.sol").write_text("contract Real {}")
            for skip_dir in ("halmos", "kontrol", "spec", "specs"):
                (root / "src" / skip_dir).mkdir()
                (root / "src" / skip_dir / "Harness.sol").write_text(
                    f"contract {skip_dir.capitalize()}Harness {{}}"
                )

            warnings: list[str] = []
            result = AHDH._iter_solidity_sources([root / "src"], warnings)
            names = [p.name for p in result]

        self.assertEqual(
            names,
            ["Real.sol"],
            f"expected only Real.sol but got {names}",
        )

    def test_graceful_no_source_returns_empty_payload_with_warning(self) -> None:
        payload = AHDH.build_payload([])

        self.assertEqual(payload["schema"], AHDH.SCHEMA)
        self.assertEqual(payload["summary"]["function_count"], 0)
        self.assertEqual(payload["summary"]["hypotheses_count"], 0)
        self.assertEqual(payload["functions"], [])
        self.assertEqual(payload["hypotheses"], [])
        self.assertTrue(any("no Solidity source paths" in warning for warning in payload["warnings"]))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(AHDH.main([]), 0)


if __name__ == "__main__":
    unittest.main()
