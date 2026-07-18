#!/usr/bin/env python3
"""Tests for tools/cross-engagement-fanout.py — Wave-7 BIG_PLAN A6."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "cross-engagement-fanout.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("cef_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cef_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


CEF = _load()


SAMPLE_TAG = {
    "verdict_id": "paste_ready/filed/FILED_cantina-192_dydx-affiliate-blocked-addr-fee-redirect-CRITICAL.md",
    "target_repo": "dydxprotocol/v4-chain",
    "audit_pin_sha": "5ee9766351ef864856a309a971b13fdd98cae2c5",
    "language": "go",
    "verdict_class": "FILED",
    "severity_final": "CRITICAL",
    "bug_class": "missing-blocked-addr-check-on-fee-distribution",
    "attack_classes_to_try": ["admin-bypass", "blocked-addr-bypass",
                              "fee-redirect", "module-account-permafreeze"],
    "sites": [
        {"file_path": "x/affiliates/keeper/msg_server.go",
         "function_name": "RegisterAffiliate",
         "shape_hash": "46c4fa3fa0768ffa"},
        {"file_path": "x/subaccounts/keeper/transfer.go",
         "function_name": "TransferFees",
         "shape_hash": "a5467f32e5bbfa2e"},
    ],
}


class TestPatternExtraction(unittest.TestCase):

    def test_extracts_basic_pattern(self):
        p = CEF.extract_pattern(SAMPLE_TAG, "dydx")
        self.assertIsNotNone(p)
        self.assertEqual(p.bug_class, "missing-blocked-addr-check-on-fee-distribution")
        self.assertEqual(p.severity, "CRITICAL")
        self.assertEqual(p.source_engagement, "dydx")
        self.assertIn("RegisterAffiliate", p.function_names)
        self.assertIn("TransferFees", p.function_names)
        self.assertIn("46c4fa3fa0768ffa", p.shape_hashes)

    def test_file_path_pattern_matches_basenames(self):
        p = CEF.extract_pattern(SAMPLE_TAG, "dydx")
        import re
        self.assertTrue(re.match(p.file_path_pattern,
                                 "external/spark/x/something/msg_server.go"))
        self.assertTrue(re.match(p.file_path_pattern,
                                 "x/affiliates/keeper/transfer.go"))
        self.assertFalse(re.match(p.file_path_pattern,
                                  "external/cosmos/x/auth/types.go"))

    def test_key_invariants_derived_from_bug_class(self):
        p = CEF.extract_pattern(SAMPLE_TAG, "dydx")
        # bug_class tokens "missing", "blocked", "addr", "check", "fee",
        # "distribution" should produce SOME key invariants
        self.assertGreater(len(p.key_invariants), 2)

    def test_engagement_repo_filter(self):
        self.assertTrue(CEF._verdict_belongs_to("dydx", "dydxprotocol/v4-chain"))
        self.assertTrue(CEF._verdict_belongs_to("spark", "buildonspark/spark"))
        self.assertFalse(CEF._verdict_belongs_to("dydx", "buildonspark/spark"))
        # cosmos-sdk verdicts SHOULD count for dydx (chain dep)
        self.assertTrue(CEF._verdict_belongs_to("dydx", "cosmos/cosmos-sdk"))


class TestDestinationScan(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dest_root = Path(self._td.name) / "external"
        self.dest_root.mkdir(parents=True)

    def tearDown(self):
        self._td.cleanup()

    def test_file_pattern_match_against_synthetic_tree(self):
        # File whose basename matches one of the source basenames
        target = self.dest_root / "buildonspark" / "x" / "transfer.go"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "package transfer\n"
            "// missing blocked addr check on fee distribution\n"
            "func TransferFees(addr Address) error { return nil }\n",
            encoding="utf-8",
        )
        # Decoy file
        decoy = self.dest_root / "buildonspark" / "x" / "subtree.go"
        decoy.write_text("package subtree\nfunc Other() {}\n", encoding="utf-8")

        pattern = CEF.extract_pattern(SAMPLE_TAG, "dydx")
        matches = CEF.scan_destination([pattern], self.dest_root, top_n=10)
        files = [m.dest_file for m in matches]
        self.assertTrue(any("transfer.go" in f for f in files),
                        f"transfer.go missing from {files}")

    def test_function_name_match(self):
        target = self.dest_root / "any.go"
        target.write_text(
            "package x\nfunc RegisterAffiliate(a string) error { return nil }\n",
            encoding="utf-8",
        )
        pattern = CEF.extract_pattern(SAMPLE_TAG, "dydx")
        matches = CEF.scan_destination([pattern], self.dest_root, top_n=10)
        # should include this file because fn-name hits
        fn_hits = [m for m in matches if m.function_name_hit]
        self.assertGreaterEqual(len(fn_hits), 1)

    def test_no_matches_on_empty_tree(self):
        pattern = CEF.extract_pattern(SAMPLE_TAG, "dydx")
        matches = CEF.scan_destination([pattern], self.dest_root, top_n=10)
        self.assertEqual(matches, [])


class TestPatternBugClassFilter(unittest.TestCase):

    def test_load_filters_by_bug_class(self):
        # Use the real repo TAGS_DIR; assert filtering by bug-class works
        all_dydx = CEF.load_source_patterns("dydx", severities={"CRITICAL", "HIGH"})
        filtered = CEF.load_source_patterns(
            "dydx", bug_class_filter="blocked-addr",
            severities={"CRITICAL", "HIGH"},
        )
        # Both lists are real; filter must be a (possibly empty) subset.
        self.assertLessEqual(len(filtered), len(all_dydx))
        for p in filtered:
            self.assertIn("blocked-addr", p.bug_class.lower())


class TestReportEmission(unittest.TestCase):

    def test_emit_report_writes_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            dest_ws = Path(td)
            pattern = CEF.extract_pattern(SAMPLE_TAG, "dydx")
            match = CEF.FanoutMatch(
                pattern_slug=pattern.slug(),
                bug_class=pattern.bug_class,
                severity=pattern.severity,
                dest_file="x/y/z.go",
                matched_function="RegisterAffiliate",
                file_pattern_hit=True,
                shape_hash_hit=False,
                function_name_hit=True,
                invariant_hits=["(?i)blocked", "(?i)addr"],
                score=0.70,
            )
            out = CEF.emit_report(dest_ws, "dydx", "spark", [pattern], [match], None)
            self.assertTrue(out.exists())
            body = out.read_text(encoding="utf-8")
            self.assertIn("Cross-engagement fanout", body)
            self.assertIn("`x/y/z.go`", body)
            self.assertIn("RegisterAffiliate", body)


if __name__ == "__main__":
    unittest.main()
