"""Tests for tools/prior-audit-completeness-check.py (GATE-PRIOR-AUDIT-COMPLETENESS).

Non-vacuous coverage (present -> X, removed -> not-X):

  1. FLAG: product X expects a Spearbit-2024 audit NOT on disk -> dedup_gap=True,
     verdict FLAG, exit 1.  (the core lane requirement)
  2. PASS: a fully-covered workspace (every expected audit on disk) ->
     verdict pass, exit 0.  (proves the FLAG isn't vacuous)
  3. missing_all_audits: an in-scope product with a known publisher but ZERO
     prior_audits on disk for it -> gap_kind == "missing_all_audits" (fail-closed).
  4. warn: no expected set supplied -> verdict warn, NOT a false pass.
  5. repo-audits-listing path: an official-repo audits/ listing supplies the
     expectation; a listed audit absent on disk -> FLAG.
  6. unit: normalize_firm / normalize_date / date_matches / product_key edges.
  7. firm-disagreement does NOT count as present (fail-closed matching).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = ROOT / "tools" / "prior-audit-completeness-check.py"

spec = importlib.util.spec_from_file_location(
    "prior_audit_completeness_check", _TOOL_PATH
)
mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
# Python 3.14 importlib quirk: register before exec.
sys.modules["prior_audit_completeness_check"] = mod
spec.loader.exec_module(mod)  # type: ignore[union-attr]

run_completeness_check = mod.run_completeness_check
main = mod.main
normalize_firm = mod.normalize_firm
normalize_date = mod.normalize_date
date_matches = mod.date_matches
product_key = mod.product_key
parse_scope_products = mod.parse_scope_products
parse_disk_audits = mod.parse_disk_audits
expected_is_present = mod.expected_is_present


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


_SCOPE_TWO_PRODUCTS = """\
# SCOPE - Example multi-product engagement

## Codebase (in-scope SOURCE)
- `morpho-org/morpho-blue` (Solidity) - cloned src/morpho-blue/
- `morpho-org/metamorpho` (Solidity) - cloned src/metamorpho/
- Docs: https://docs.morpho.org

## Severity
Critical: theft of funds.
"""

_SCOPE_SINGLE_PRODUCT = """\
# SCOPE - Single product

## Codebase
- `ssvlabs/ssv-network` (Solidity)
"""

_EXPECTED_MANIFEST_PRODUCTS = {
    "products": {
        "morpho-org/morpho-blue": [
            {"firm": "Spearbit", "date": "2024-01-15"},
            {"firm": "Cantina", "date": "2024-03"},
        ],
        "morpho-org/metamorpho": [
            {"firm": "Spearbit", "date": "2024-04"},
        ],
    }
}


class CoreFlagAndPass(unittest.TestCase):
    def _build_ws(self, tmp: Path, disk_files: list[str]) -> Path:
        ws = tmp / "ws"
        _write(ws / "SCOPE.md", _SCOPE_TWO_PRODUCTS)
        for f in disk_files:
            _write(ws / "prior_audits" / f, "audit body\n")
        _write(tmp / "expected.json", json.dumps(_EXPECTED_MANIFEST_PRODUCTS))
        return ws

    def test_flag_when_expected_spearbit_2024_missing(self) -> None:
        """Lane requirement: product expects Spearbit-2024 audit not on disk -> FLAG."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # On disk: ONLY the Cantina morpho-blue audit. The two Spearbit
            # expectations (morpho-blue 2024-01 + metamorpho 2024-04) are absent.
            ws = self._build_ws(tmp, [
                "2024-03-20_Cantina_morpho-blue_v1.txt",
            ])
            res = run_completeness_check(ws, expected_manifest=tmp / "expected.json")
            self.assertEqual(res["verdict"], "FLAG", res)
            gap_firms = {
                (g["expected_audit"]["firm"], g["product_key"]) for g in res["gaps"]
            }
            self.assertIn(("Spearbit", "morphoblue"), gap_firms)
            self.assertIn(("Spearbit", "metamorpho"), gap_firms)
            # The Cantina morpho-blue audit IS present -> not a gap.
            present_rows = [r for r in res["report"] if r["present"]]
            self.assertTrue(any(
                r["expected_audit"]["firm"] == "Cantina" for r in present_rows
            ), res["report"])

    def test_pass_when_fully_covered(self) -> None:
        """Removed-symptom control: all expected audits on disk -> pass (no gap)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = self._build_ws(tmp, [
                "2024-01-15_Spearbit_morpho-blue.pdf",
                "2024-03-02_Cantina_morpho-blue_v1.txt",
                "2024-04-09_Spearbit_metamorpho.pdf",
            ])
            res = run_completeness_check(ws, expected_manifest=tmp / "expected.json")
            self.assertEqual(res["verdict"], "pass", res)
            self.assertEqual(res["gaps"], [], res["gaps"])

    def test_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws_flag = self._build_ws(tmp, ["2024-03-20_Cantina_morpho-blue.txt"])
            rc = main([str(ws_flag), "--expected", str(tmp / "expected.json")])
            self.assertEqual(rc, 1)

            tmp2 = Path(tempfile.mkdtemp())
            ws_pass = self._build_ws(tmp2, [
                "2024-01-15_Spearbit_morpho-blue.pdf",
                "2024-03-02_Cantina_morpho-blue.txt",
                "2024-04-09_Spearbit_metamorpho.pdf",
            ])
            rc2 = main([str(ws_pass), "--expected", str(tmp2 / "expected.json")])
            self.assertEqual(rc2, 0)


class MissingAllAuditsHardGap(unittest.TestCase):
    def test_product_with_zero_prior_audits_flagged_missing_all(self) -> None:
        """Fail-closed: known publisher + zero disk audits for a product -> missing_all_audits."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            _write(ws / "SCOPE.md", _SCOPE_TWO_PRODUCTS)
            # morpho-blue HAS its expected audits on disk; metamorpho has NONE.
            _write(ws / "prior_audits" / "2024-01-15_Spearbit_morpho-blue.pdf", "x")
            _write(ws / "prior_audits" / "2024-03-02_Cantina_morpho-blue.txt", "x")
            _write(tmp / "expected.json", json.dumps(_EXPECTED_MANIFEST_PRODUCTS))
            res = run_completeness_check(ws, expected_manifest=tmp / "expected.json")
            self.assertEqual(res["verdict"], "FLAG", res)
            meta_gaps = [g for g in res["gaps"] if g["product_key"] == "metamorpho"]
            self.assertTrue(meta_gaps, res["gaps"])
            self.assertEqual(meta_gaps[0]["gap_kind"], "missing_all_audits", meta_gaps)
            # morpho-blue is fully covered -> no morpho-blue gap rows.
            self.assertFalse(
                [g for g in res["gaps"] if g["product_key"] == "morphoblue"], res["gaps"]
            )


class WarnWhenNoExpectedSet(unittest.TestCase):
    def test_warn_not_false_pass(self) -> None:
        """No expected set -> warn (cannot assert completeness), not a false pass."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            _write(ws / "SCOPE.md", _SCOPE_TWO_PRODUCTS)
            _write(ws / "prior_audits" / "2024-01-15_Spearbit_morpho-blue.pdf", "x")
            res = run_completeness_check(ws)
            self.assertEqual(res["verdict"], "warn", res)
            self.assertEqual(res["reason"], "no_expected_audit_set_supplied")
            rc = main([str(ws)])
            self.assertEqual(rc, 0)  # warn is not a hard gate


class RepoAuditsListingPath(unittest.TestCase):
    def test_listing_dir_supplies_expectation_and_flags_missing(self) -> None:
        """An official-repo audits/ listing supplies expectations; absent on disk -> FLAG."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            _write(ws / "SCOPE.md", _SCOPE_SINGLE_PRODUCT)
            # disk has NO prior audits at all
            (ws / "prior_audits").mkdir(parents=True, exist_ok=True)
            # official-repo audits/ listing (a directory of filenames)
            listing = tmp / "official_audits"
            _write(listing / "2024-07-04_Quantstamp_v1.2.0.pdf", "")
            _write(listing / "2023-03-24_Quantstamp_v1.0.0-rc3.pdf", "")
            res = run_completeness_check(
                ws,
                repo_audits_listings=[("ssvlabs/ssv-network", listing)],
            )
            self.assertEqual(res["verdict"], "FLAG", res)
            self.assertEqual(res["expected_count"], 2, res)
            self.assertEqual(len(res["gaps"]), 2, res["gaps"])

    def test_listing_file_one_per_line_present_passes(self) -> None:
        """When the listed audits ARE on disk -> pass (control for the FLAG above)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            _write(ws / "SCOPE.md", _SCOPE_SINGLE_PRODUCT)
            _write(ws / "prior_audits" / "2024-07-04_Quantstamp_v1.2.0.txt", "x")
            listing_file = tmp / "audits_listing.txt"
            _write(listing_file, "# official repo audits/\n2024-07-04_Quantstamp_v1.2.0.pdf\n")
            res = run_completeness_check(
                ws,
                repo_audits_listings=[("ssvlabs/ssv-network", listing_file)],
            )
            self.assertEqual(res["verdict"], "pass", res)


class FirmDisagreementFailsClosed(unittest.TestCase):
    def test_same_date_different_firm_is_not_present(self) -> None:
        """A disk audit with the right date but WRONG firm must not satisfy expectation."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            _write(ws / "SCOPE.md", _SCOPE_SINGLE_PRODUCT)
            # disk: Quantstamp 2024-07. expected: Spearbit 2024-07. firm differs.
            _write(ws / "prior_audits" / "2024-07-04_Quantstamp_v1.2.0.txt", "x")
            expected = {"products": {"ssvlabs/ssv-network": [
                {"firm": "Spearbit", "date": "2024-07"},
            ]}}
            _write(tmp / "expected.json", json.dumps(expected))
            res = run_completeness_check(ws, expected_manifest=tmp / "expected.json")
            self.assertEqual(res["verdict"], "FLAG", res)
            self.assertEqual(len(res["gaps"]), 1, res["gaps"])


class UnitNormalization(unittest.TestCase):
    def test_normalize_firm_aliases(self) -> None:
        self.assertEqual(normalize_firm("Trail-of-Bits"), "trailofbits")
        self.assertEqual(normalize_firm("ToB"), "trailofbits")
        self.assertEqual(normalize_firm("OpenZeppelin"), "openzeppelin")
        self.assertEqual(normalize_firm("OZ"), "openzeppelin")
        self.assertEqual(normalize_firm("Spearbit"), "spearbit")
        self.assertEqual(normalize_firm(""), "")

    def test_normalize_date_granularity(self) -> None:
        self.assertEqual(normalize_date("2024-01-15"), "2024-01")
        self.assertEqual(normalize_date("2024"), "2024")
        self.assertEqual(normalize_date("2024_07_04"), "2024-07")
        self.assertEqual(normalize_date("no-date-here"), "")

    def test_date_matches_coarser_granularity(self) -> None:
        # expected year-only matches disk full date
        self.assertTrue(date_matches("2024-01-15", "2024"))
        # expected year-month matches disk same month
        self.assertTrue(date_matches("2024-07-04", "2024-07"))
        # different months do not match when expected is month-precise
        self.assertFalse(date_matches("2024-01-15", "2024-07"))
        # FAIL-CLOSED / no over-credit: a year-only disk date must NOT satisfy a
        # month-precise expectation (cannot confirm it is the same audit).
        self.assertFalse(date_matches("2024", "2024-07"))
        # but a year-only expectation IS satisfied by a year-only disk date
        self.assertTrue(date_matches("2024", "2024"))
        # empty expected matches anything
        self.assertTrue(date_matches("2024-01-15", ""))

    def test_product_key_collision(self) -> None:
        self.assertEqual(product_key("morpho-org/morpho-blue"), product_key("morpho-blue"))
        self.assertEqual(product_key("ssvlabs/ssv-network"), "ssvnetwork")

    def test_parse_scope_products_extracts_slugs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "SCOPE.md", _SCOPE_TWO_PRODUCTS)
            products = parse_scope_products(ws)
            self.assertIn("morpho-org/morpho-blue", products)
            self.assertIn("morpho-org/metamorpho", products)
            # docs URL must not be treated as a product
            self.assertFalse(any("docs.morpho" in p for p in products))

    def test_parse_disk_audits_filename_parse(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "prior_audits" / "2023-10-30_Quantstamp_v1.0.2.txt", "x")
            disk = parse_disk_audits(ws)
            self.assertTrue(disk["present"])
            self.assertEqual(len(disk["audits"]), 1)
            self.assertEqual(disk["audits"][0]["firm"], "quantstamp")
            self.assertEqual(disk["audits"][0]["date"], "2023-10")


class ErrorHandling(unittest.TestCase):
    def test_missing_workspace_errors(self) -> None:
        res = run_completeness_check(Path("/nonexistent/ws/xyz"))
        self.assertEqual(res["verdict"], "error", res)

    def test_main_bad_listing_spec_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            _write(ws / "SCOPE.md", _SCOPE_SINGLE_PRODUCT)
            rc = main([str(ws), "--repo-audits-listing", "no-equals-sign"])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
