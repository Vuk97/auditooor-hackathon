"""Tests for tools/function-signature-extractor.py — Go path."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "function-signature-extractor.py"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "fn_sig_extractor_go"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_fse", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class GoExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        sample_path = FIXTURE_DIR / "sample.go"
        self.text = sample_path.read_text()
        self.recs = self.tool.extract_go_functions(self.text, "sample.go")
        self.by_name = {r["function_name"]: r for r in self.recs}

    def test_extracts_all_four_functions(self) -> None:
        names = set(self.by_name.keys())
        self.assertEqual(
            names,
            {"RegisterAffiliate", "UpdateAffiliateTiers", "unexportedHelper", "MultiReturn"},
            f"got {names}",
        )

    def test_visibility_correct(self) -> None:
        self.assertEqual(self.by_name["RegisterAffiliate"]["visibility"], "exported")
        self.assertEqual(self.by_name["unexportedHelper"]["visibility"], "unexported")

    def test_register_affiliate_has_no_authority_guard(self) -> None:
        # The bug — RegisterAffiliate has NO authority-check while UpdateAffiliateTiers does
        ra = self.by_name["RegisterAffiliate"]
        ua = self.by_name["UpdateAffiliateTiers"]
        self.assertNotIn("authority-check", ra["guards_detected"])
        self.assertIn("authority-check", ua["guards_detected"])

    def test_receiver_type_detection(self) -> None:
        self.assertEqual(self.by_name["RegisterAffiliate"]["receiver_type"], "msgServer")
        # MultiReturn uses *Keeper (pointer)
        mr = self.by_name["MultiReturn"]
        self.assertEqual(mr["receiver_type"], "Keeper")
        self.assertIn("pointer-receiver", mr["modifiers"])

    def test_multi_return_parsed(self) -> None:
        mr = self.by_name["MultiReturn"]
        self.assertEqual(len(mr["return_types"]), 3)
        # last return is error
        self.assertIn("error", mr["return_types"][-1])

    def test_params_for_register_affiliate(self) -> None:
        ra = self.by_name["RegisterAffiliate"]
        param_types = [p["type"] for p in ra["params"]]
        self.assertIn("context.Context", param_types)
        # second param is the *types.MsgRegisterAffiliate
        self.assertTrue(any("MsgRegisterAffiliate" in t for t in param_types))


if __name__ == "__main__":
    unittest.main()
