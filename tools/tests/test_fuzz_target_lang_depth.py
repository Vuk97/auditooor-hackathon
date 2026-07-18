#!/usr/bin/env python3
"""test_fuzz_target_lang_depth.py

Enforcement-gap G-3 (2026-07-03): a Go/Rust fuzz-target worklist row terminalized on
ANY campaign-receipt token match - so a mixed ws could green with the Go/Rust arm NEVER
fuzzed at depth (core-coverage defers Go/Rust to "their own axes"; this gate accepted a
cross-language credit). fuzz-target-completeness now requires a Go/Rust campaign-credited
row to ALSO show language-appropriate DEPTH (Go fuzztime / Rust PROPTEST_CASES|cargo-fuzz),
under AUDITOOOR_FUZZ_TARGET_LANG_DEPTH_STRICT (default OFF -> legacy behavior).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "fuzz-target-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("ftc_depth", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["ftc_depth"] = m
    spec.loader.exec_module(m)
    return m


class TestFuzzTargetLangDepth(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        for e in ("AUDITOOOR_FUZZ_TARGET_STRICT", "AUDITOOOR_FUZZ_TARGET_LANG_DEPTH_STRICT"):
            os.environ.pop(e, None)

    def tearDown(self):
        for e in ("AUDITOOOR_FUZZ_TARGET_STRICT", "AUDITOOOR_FUZZ_TARGET_LANG_DEPTH_STRICT"):
            os.environ.pop(e, None)

    def _ws(self, receipt: dict):
        d = Path(tempfile.mkdtemp())
        a = d / ".auditooor"
        a.mkdir()
        (a / "fuzz_targets.jsonl").write_text(json.dumps(
            {"target_id": "vault_keeper", "asset_path": "src/vault/keeper.go", "fn_cluster": "reconcile"}) + "\n")
        (a / "fuzz_campaign_receipt.json").write_text(json.dumps(receipt))
        return d

    def test_lang_of_row_go_and_rust(self):
        self.assertEqual(self.m._lang_of_row({"asset_path": "src/x/keeper.go"}), "go")
        self.assertEqual(self.m._lang_of_row({"asset_path": "src/lib.rs"}), "rust")
        self.assertEqual(self.m._lang_of_row({"asset_path": "src/A.sol"}), "")

    def test_go_row_without_fuzztime_opens_under_depth_strict(self):
        ws = self._ws({"contract": "vault_keeper", "asset": "src/vault/keeper.go", "calls": 500000})
        # default: campaign-receipt credits the row (legacy behavior)
        self.assertEqual(self.m.check(ws)["verdict"], "pass-fuzz-target-complete")
        # depth-strict: no Go fuzztime -> the row stays OPEN -> fail
        os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
        os.environ["AUDITOOOR_FUZZ_TARGET_LANG_DEPTH_STRICT"] = "1"
        r = self.m.check(ws)
        self.assertEqual(r["verdict"], "fail-fuzz-target-incomplete")
        self.assertEqual(len(r["open"]), 1)
        self.assertIn("no-go-depth", r["open"][0].get("reason", ""))

    def test_go_row_with_fuzztime_credited(self):
        ws = self._ws({"contract": "vault_keeper", "asset": "src/vault/keeper.go", "fuzztime": "60s"})
        os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
        os.environ["AUDITOOOR_FUZZ_TARGET_LANG_DEPTH_STRICT"] = "1"
        self.assertEqual(self.m.check(ws)["verdict"], "pass-fuzz-target-complete")

    def test_depth_evidence_rust_proptest(self):
        d = Path(tempfile.mkdtemp())
        (d / ".auditooor").mkdir()
        (d / ".auditooor" / "fuzz_campaign_receipt.json").write_text('{"PROPTEST_CASES": 20000}')
        self.assertTrue(self.m._lang_depth_evidence(d, "rust"))
        self.assertFalse(self.m._lang_depth_evidence(d, "go"))  # no go token


if __name__ == "__main__":
    unittest.main()
