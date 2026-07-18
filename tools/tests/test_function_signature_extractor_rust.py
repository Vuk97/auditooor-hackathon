"""Tests for tools/function-signature-extractor.py — Rust path."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "function-signature-extractor.py"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "fn_sig_extractor_rust"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_fse_rust", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class RustExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        sample_path = FIXTURE_DIR / "sample.rs"
        self.text = sample_path.read_text(encoding="utf-8")
        self.recs = self.tool.extract_rust_functions(self.text, "sample.rs")
        self.by_name = {r["function_name"]: r for r in self.recs}

    def test_extracts_expected_function_names(self) -> None:
        self.assertEqual(
            set(self.by_name.keys()),
            {"process_message", "apply", "helper", "settle"},
        )

    def test_parses_return_type_with_generics(self) -> None:
        proc = self.by_name["process_message"]
        self.assertEqual(proc["return_types"], ["Result<(), ProgramError>"])

    def test_method_receiver_is_detected_and_self_not_in_params(self) -> None:
        apply_fn = self.by_name["apply"]
        self.assertEqual(apply_fn["receiver_type"], "Self")
        param_names = [p["name"] for p in apply_fn["params"]]
        self.assertNotIn("self", param_names)
        param_types = [p["type"] for p in apply_fn["params"]]
        self.assertIn("Instruction", param_types)
        self.assertIn("Pubkey", param_types)

    def test_where_clause_does_not_pollute_return_type(self) -> None:
        settle = self.by_name["settle"]
        self.assertEqual(settle["return_types"], ["Result<(u64, u64), ProgramError>"])


if __name__ == "__main__":
    unittest.main()
