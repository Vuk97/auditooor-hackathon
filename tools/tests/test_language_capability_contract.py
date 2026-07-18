#!/usr/bin/env python3
"""Focused tests for the canonical language capability contract."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "language-capability-contract.py"
CONTRACT_PATH = ROOT / "reference" / "language_capabilities.json"


def load_tool():
    spec = importlib.util.spec_from_file_location("language_capability_contract", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LanguageCapabilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        cls.contract = cls.tool.load_contract(CONTRACT_PATH)

    def test_contract_validates_and_oscript_is_parser_backed_but_not_semantic(self):
        self.assertEqual(self.tool.validate_contract(self.contract), [])
        oscript = next(row for row in self.contract["languages"] if row["canonical"] == "oscript")
        self.assertEqual(oscript["parser_extractor"]["tier"], "AST-backed")
        self.assertEqual(oscript["dataflow_substrate"]["tier"], "AST-backed")
        self.assertEqual(oscript["evidence_tier"], "AST-backed")
        self.assertIn("tools/oscript-ast-dataflow.py", json.dumps(oscript))

    def test_javascript_uses_ast_backed_route(self):
        row = next(row for row in self.contract["languages"] if row["canonical"] == "javascript")
        self.assertEqual(row["parser_extractor"]["tier"], "AST-backed")
        self.assertIn("tools/js-dataflow.py", row["parser_extractor"]["tool_refs"])

    def test_mixed_go_rust_solidity_query(self):
        receipts = [
            {"language": "go", "backend": "go/ssa", "confidence": "semantic-ssa"},
            {"language": "rust", "backend": "rustc-mir.defuse-bridge", "confidence": "semantic-ssa"},
            {"language": "solidity", "backend": "slither.analyses.data_dependency", "confidence": "semantic-ssa"},
        ]
        report = self.tool.query_contract(
            self.contract, {"go", "rust", "solidity"}, ("dataflow",), receipts
        )
        self.assertEqual(report["present_languages"], ["go", "rust", "solidity"])
        self.assertEqual(report["blocked_languages"], [])

    def test_semantic_phase_minimums_are_explicit(self):
        minimums = self.contract["phase_minimum_tiers"]
        for phase in ("dataflow", "reasoner", "engine", "depth", "fuzz"):
            self.assertEqual(minimums[phase], "semantic/compiler-backed")
        self.assertEqual(minimums["ast"], "AST-backed")

    def test_oscript_blocks_all_semantic_drive_phases(self):
        for phase in ("dataflow", "reasoner", "engine", "depth", "fuzz"):
            report = self.tool.query_contract(self.contract, {"oscript"}, (phase,))
            self.assertFalse(report["ok"], phase)
            self.assertEqual(report["blocked_languages"], ["oscript"])

    def test_rust_requires_mir_receipt_for_semantic_dataflow(self):
        blocked = self.tool.query_contract(self.contract, {"rust"}, ("dataflow",))
        self.assertFalse(blocked["ok"])
        self.assertIn("semantic_backend_receipt", blocked["languages"][0]["missing"])
        available = self.tool.query_contract(
            self.contract,
            {"rust"},
            ("dataflow",),
            [{"language": "rust", "backend": "mir", "confidence": "semantic-ssa"}],
        )
        self.assertTrue(available["ok"])

    def test_go_requires_semantic_ssa_receipt(self):
        blocked = self.tool.query_contract(self.contract, {"go"}, ("dataflow",))
        self.assertFalse(blocked["ok"])
        available = self.tool.query_contract(
            self.contract,
            {"go"},
            ("dataflow",),
            [{"language": "go", "backend": "go-ssa", "confidence": "semantic-ssa"}],
        )
        self.assertTrue(available["ok"])

    def test_solidity_requires_slither_receipt(self):
        blocked = self.tool.query_contract(self.contract, {"solidity"}, ("dataflow",))
        self.assertFalse(blocked["ok"])
        available = self.tool.query_contract(
            self.contract,
            {"solidity"},
            ("dataflow",),
            [{"language": "solidity", "backend": "slither", "confidence": "semantic-ssa"}],
        )
        self.assertTrue(available["ok"])

    def test_javascript_ast_is_not_semantic_dataflow(self):
        ast_report = self.tool.query_contract(self.contract, {"javascript"}, ("ast",))
        self.assertTrue(ast_report["ok"])
        dataflow_report = self.tool.query_contract(self.contract, {"javascript"}, ("dataflow",))
        self.assertFalse(dataflow_report["ok"])

    def test_oscript_parser_backed_ast_is_not_semantic_dataflow(self):
        ast_report = self.tool.query_contract(self.contract, {"oscript"}, ("ast",))
        self.assertTrue(ast_report["ok"])
        dataflow_report = self.tool.query_contract(self.contract, {"oscript"}, ("dataflow",))
        self.assertFalse(dataflow_report["ok"])

    def test_nonsemantic_language_tiers_fail_semantic_minimum(self):
        for language in ("typescript", "oscript", "circom"):
            report = self.tool.query_contract(self.contract, {language}, ("dataflow",))
            self.assertFalse(report["ok"], language)

    def test_unknown_inventory_language_is_reported(self):
        report = self.tool.query_contract(self.contract, {"go", "madeup"}, ("source",))
        self.assertEqual(report["unknown_inventory_languages"], ["madeup"])
        self.assertFalse(report["ok"])

    def test_duplicate_alias_and_extension_are_rejected(self):
        mutated = json.loads(json.dumps(self.contract))
        mutated["languages"][1]["aliases"] = ["evm"]
        mutated["languages"][1]["extensions"] = [".sol"]
        errors = self.tool.validate_contract(mutated)
        self.assertTrue(any("duplicate alias" in error for error in errors))
        self.assertTrue(any("duplicate extension" in error for error in errors))

    def test_missing_referenced_tool_is_rejected(self):
        mutated = json.loads(json.dumps(self.contract))
        mutated["languages"][0]["parser_extractor"]["tool_refs"].append("tools/not-real.py")
        errors = self.tool.validate_contract(mutated)
        self.assertTrue(any("missing tool tools/not-real.py" in error for error in errors))

    def test_unsupported_applicable_phase_fails(self):
        report = self.tool.query_contract(self.contract, {"oscript"}, ("engine_substrate_route",))
        self.assertEqual(report["blocked_languages"], ["oscript"])
        self.assertFalse(report["ok"])

    def test_cli_query_returns_nonzero_for_unsupported_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "inventory.json"
            inventory.write_text(json.dumps({"languages": ["oscript"]}), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(TOOL_PATH), "query", "--inventory", str(inventory), "--phase", "engine", "--json"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn('"status": "blocked"', result.stdout)


if __name__ == "__main__":
    unittest.main()
