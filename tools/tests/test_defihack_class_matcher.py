#!/usr/bin/env python3
"""Tests for tools/defihack-class-matcher.py.

Stdlib-only, hermetic via tempfile.TemporaryDirectory. Covers:
1. Catalog loads without error and has ≥20 rows.
2. ≥5 rows have mechanism + ≥1 grep_predicate.
3. Tool runs against a mock workspace dir and produces match_report.md.
4. Vendor-path suppression works (hits in external/ are excluded).
5. Summary line is printed on stdout.
"""
from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "defihack-class-matcher.py"
CATALOG_PATH = REPO_ROOT / "defihacklabs" / "catalog.yaml"


def _load_module():
    spec = importlib.util.spec_from_file_location("defihack_class_matcher", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["defihack_class_matcher"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


class TestCatalogLoad(unittest.TestCase):
    def test_catalog_loads_without_error(self):
        rows = MOD._load_catalog(CATALOG_PATH)
        self.assertIsInstance(rows, list)
        self.assertGreater(len(rows), 0, "catalog must have at least one row")

    def test_catalog_has_20_rows(self):
        rows = MOD._load_catalog(CATALOG_PATH)
        self.assertGreaterEqual(len(rows), 20, f"expected ≥20 rows, got {len(rows)}")

    def test_rows_have_id_and_attack_class(self):
        rows = MOD._load_catalog(CATALOG_PATH)
        for row in rows:
            self.assertIn("id", row, f"row missing id: {row}")
            self.assertIn("attack_class", row, f"row missing attack_class: {row}")

    def test_at_least_5_rows_have_mechanism_and_predicates(self):
        rows = MOD._load_catalog(CATALOG_PATH)
        viable = [
            r for r in rows
            if r.get("mechanism") and r.get("grep_predicates")
            and len(r["grep_predicates"]) >= 1
        ]
        self.assertGreaterEqual(
            len(viable), 5,
            f"expected ≥5 rows with mechanism+predicates, got {len(viable)}"
        )

    def test_gap_rows_have_predicates(self):
        """All 'gap' status rows must have grep_predicates (they need detectors)."""
        rows = MOD._load_catalog(CATALOG_PATH)
        gap_rows = [r for r in rows if r.get("detector_status") == "gap"]
        for row in gap_rows:
            self.assertTrue(
                row.get("grep_predicates"),
                f"gap row {row.get('id')} has no grep_predicates"
            )


class TestMatcherMockWorkspace(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

        # Plant a Solidity file with patterns that match dhl-005 (spot LP oracle)
        sol_dir = self.ws / "src"
        sol_dir.mkdir(parents=True)
        (sol_dir / "PriceOracle.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "function getPrice() external view returns (uint) {\n"
            "    (,, uint r0, uint r1,,) = IUniswapV2Pair(pair).getReserves();\n"
            "    return r0 * 1e18 / r1;\n"
            "}\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_produces_match_report(self):
        out_dir = self.ws / "scan-results" / "defihack-match-test"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = MOD.main([
                "--workspace", str(self.ws),
                "--catalog", str(CATALOG_PATH),
                "--out-dir", str(out_dir),
                "--quiet",
            ])
        self.assertEqual(rc, 0, f"tool exited non-zero; stdout: {buf.getvalue()}")
        report = out_dir / "match_report.md"
        self.assertTrue(report.exists(), "match_report.md was not created")
        content = report.read_text(encoding="utf-8")
        self.assertIn("# DeFiHackLabs class-matcher report", content)

    def test_summary_line_in_stdout(self):
        out_dir = self.ws / "scan-results" / "defihack-match-test2"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = MOD.main([
                "--workspace", str(self.ws),
                "--catalog", str(CATALOG_PATH),
                "--out-dir", str(out_dir),
                "--quiet",
            ])
        self.assertEqual(rc, 0)
        output = buf.getvalue()
        self.assertIn("[defihack-match]", output)
        self.assertIn("rows scanned", output)
        self.assertIn("candidate-detector seeds emitted", output)

    def test_dhl005_hits_in_mock_workspace(self):
        """getReserves() pattern from dhl-005 should hit the planted Solidity file."""
        out_dir = self.ws / "scan-results" / "defihack-match-test3"
        buf = io.StringIO()
        with redirect_stdout(buf):
            MOD.main([
                "--workspace", str(self.ws),
                "--catalog", str(CATALOG_PATH),
                "--out-dir", str(out_dir),
                "--quiet",
            ])
        report = (out_dir / "match_report.md").read_text(encoding="utf-8")
        # The report should mention dhl-005 with hits
        self.assertIn("dhl-005", report)
        # And should show at least the getReserves match
        self.assertIn("getReserves", report)


class TestVendorSuppression(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

        # Plant pattern in vendor path (should be suppressed)
        vendor_dir = self.ws / "vendor" / "oracle"
        vendor_dir.mkdir(parents=True)
        (vendor_dir / "Oracle.sol").write_text(
            "function getPrice() external { IUniswapV2Pair(p).getReserves(); }\n",
            encoding="utf-8",
        )

        # Plant same pattern in src path (should NOT be suppressed)
        src_dir = self.ws / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "Real.sol").write_text(
            "function getPrice() external { IUniswapV2Pair(p).getReserves(); }\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_vendor_paths_suppressed(self):
        """Hits in vendor/ must not appear in report; hits in src/ must appear."""
        out_dir = self.ws / "scan-results" / "vendor-test"
        buf = io.StringIO()
        with redirect_stdout(buf):
            MOD.main([
                "--workspace", str(self.ws),
                "--catalog", str(CATALOG_PATH),
                "--out-dir", str(out_dir),
                "--quiet",
            ])
        report = (out_dir / "match_report.md").read_text(encoding="utf-8")
        # vendor path must not appear
        self.assertNotIn("vendor/oracle/Oracle.sol", report,
                         "vendor path leaked into match report")
        # src path must appear (dhl-005 getReserves() match)
        self.assertIn("src/Real.sol", report,
                      "expected src/Real.sol to appear in report")


if __name__ == "__main__":
    unittest.main()
