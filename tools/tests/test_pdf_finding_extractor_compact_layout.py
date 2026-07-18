"""Tests for the Pashov compact-layout extractor fallback (Task #195).

Real-world anchor: the DefiApp 2026-05-23 Pashov audit PDF carries 3
findings on a single body page. Each ``[L-NN]`` heading appears 3 times
in the PDF text layer (TOC, summary-of-findings table, real body) and
the body anchors lack a ``Description:`` header. Before this fix the
extractor emitted 0/3 records via the W2.4 ETL because:

* The TOC anchor for ``[L-03]`` outscored the body anchor (it absorbed
  every interior page between the TOC and the next anchor on page 5).
* L-01 and L-02 body anchors stayed clean but ``_pashov_section_after_header``
  returned ``""`` for the description because no ``Description:`` header
  was present.

The fix adds two cooperating mechanisms:

1. ``_pashov_filter_compact_layout_anchors`` drops TOC and summary-table
   noise anchors when a sibling body-role anchor exists in the same
   ``(code, finding_index)`` group.
2. ``_pashov_body_fallback_description`` falls back to cleaned body text
   when no ``Description``/``Summary``/``Impact`` header is present.

Tests cover the DefiApp-shape compact layout, N=2 variant, backward
compatibility with single-finding-per-page PDFs, and the empty-PDF
graceful path.

R36 citation: pathspec for LANE-195-PDF-EXTRACTOR-COMPACT registered
via ``tools/agent-pathspec-register.py`` (see
``.auditooor/agent_pathspec.json``).
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LIB_DIR = REPO_ROOT / "tools" / "lib"
FIXTURE_PKG = REPO_ROOT / "tools" / "tests" / "fixtures" / "audit_firm_pdf_samples"

sys.path.insert(0, str(LIB_DIR))
sys.path.insert(0, str(FIXTURE_PKG))

import pdf_finding_extractor  # noqa: E402
import _pashov_fixture_builder  # noqa: E402


class PashovCompactLayoutTests(unittest.TestCase):
    """Compact-layout Pashov PDF extraction (DefiApp 2026-05-23 pattern)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _pashov_fixture_builder.ensure_fixtures()

    # ------------------------------------------------------------------
    # Anchor-role classifier (white-box unit tests).
    # ------------------------------------------------------------------

    def test_anchor_role_classifier_toc_trailing_page_number(self) -> None:
        # TOC entries end with a trailing page number digit run.
        cases = [
            "Layerzero config file includes 1-of-1 DVN setup 7",
            "No rate limits configured on any peer 7",
            "Inconsistent multisig threshold between EVM chain and Solana chain 7",
            "A short title 12",
        ]
        for raw_title in cases:
            self.assertEqual(
                pdf_finding_extractor._pashov_anchor_role(raw_title),
                "toc",
                f"expected TOC role for {raw_title!r}",
            )

    def test_anchor_role_classifier_summary_trailing_severity_status(self) -> None:
        # Summary-table entries end with severity + status.
        cases = [
            "Layerzero config file includes 1-of-1 DVN setupLow Acknowledged",
            "No rate limits configured on any peer Low Acknowledged",
            "First compact medium finding Medium Fixed",
            "Second compact severity Critical Resolved",
        ]
        for raw_title in cases:
            self.assertEqual(
                pdf_finding_extractor._pashov_anchor_role(raw_title),
                "summary",
                f"expected SUMMARY role for {raw_title!r}",
            )

    def test_anchor_role_classifier_body_clean_title(self) -> None:
        # Real body titles have no TOC / summary trailer.
        cases = [
            "Layerzero config file includes 1-of-1 DVN setup",
            "No rate limits configured on any peer",
            "Inconsistent multisig threshold between EVM chain and Solana chain",
            "Reentrancy in withdraw allows fund theft",
        ]
        for raw_title in cases:
            self.assertEqual(
                pdf_finding_extractor._pashov_anchor_role(raw_title),
                "body",
                f"expected BODY role for {raw_title!r}",
            )

    # ------------------------------------------------------------------
    # _pashov_body_fallback_description (white-box).
    # ------------------------------------------------------------------

    def test_body_fallback_description_returns_cleaned_body_when_substantive(
        self,
    ) -> None:
        body = (
            "\nEven so the on-chain data shows the 3-of-3 DVN setups for OFT token,\n"
            "project's Layerzero config file layerzero.config.ts still uses 1-of-1\n"
            "setup which is vulnerable.\n"
            "Pashov Audit Group DefiApp Security Review\n"
            "7 / 8\n"
            "It's recommended to update the config file to reflect the current setup.\n"
        )
        out = pdf_finding_extractor._pashov_body_fallback_description(body)
        # Page-header noise stripped.
        self.assertNotIn("Pashov Audit Group DefiApp Security Review", out)
        # Page-footer ``7 / 8`` stripped.
        self.assertNotIn("7 / 8", out)
        # Substantive body preserved.
        self.assertIn("3-of-3 DVN setups", out)
        self.assertIn("update the config file", out)

    def test_body_fallback_description_returns_empty_for_short_body(self) -> None:
        # Body shorter than 50 chars of substantive text -> empty.
        body = "\nShort body.\n"
        self.assertEqual(
            pdf_finding_extractor._pashov_body_fallback_description(body),
            "",
        )

    def test_body_fallback_description_strips_low_findings_subheading(self) -> None:
        body = (
            "\nLow findings\n"
            "The vulnerability at target/contracts/Foo.sol:L42 allows a privileged\n"
            "caller to set a fee recipient without validation, exposing the protocol.\n"
            "Consider adding an onlyOwner modifier.\n"
        )
        out = pdf_finding_extractor._pashov_body_fallback_description(body)
        self.assertNotIn("Low findings", out)
        self.assertIn("Foo.sol:L42", out)

    # ------------------------------------------------------------------
    # End-to-end: compact 3-findings-per-page PDF.
    # ------------------------------------------------------------------

    def test_compact_three_findings_pdf_yields_three_findings(self) -> None:
        """Pre-fix: 0 findings emitted. Post-fix: 3 findings at >=0.65 confidence."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_compact_three_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        # The TOC + summary-table anchors are filtered out; only the
        # 3 body anchors survive dedup.
        self.assertEqual(
            len(findings),
            3,
            f"expected 3 findings, got {len(findings)}: titles="
            f"{[f.title for f in findings]}",
        )
        # All three above the 0.65 ETL emission threshold.
        for f in findings:
            self.assertGreaterEqual(
                f.parser_confidence,
                0.65,
                f"finding {f.severity_code}-{f.finding_index} below threshold: "
                f"{f.parser_confidence}, warnings={f.parser_warnings}",
            )
        # All three carry the compact-layout fallback warning.
        for f in findings:
            self.assertIn(
                "pashov-compact-layout-description-fallback",
                f.parser_warnings,
                f"missing compact-layout warning for {f.title!r}",
            )
            self.assertIn(
                "pashov-compact-layout-anchor-filtered",
                f.parser_warnings,
                f"missing anchor-filter warning for {f.title!r}",
            )

    def test_compact_three_findings_descriptions_carry_real_body_content(
        self,
    ) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_compact_three_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        by_idx = {f.finding_index: f for f in findings}
        # L-01: description mentions the real body anchor's prose.
        self.assertIn("fooBar parameter", by_idx[1].description)
        self.assertNotIn("Methodology", by_idx[1].description)
        # L-02: description mentions the real body anchor's prose.
        self.assertIn("numeric codes", by_idx[2].description)
        # L-03: real body wins dedup (not the TOC anchor).
        self.assertIn("storage slot", by_idx[3].description)
        # L-03 must NOT contain the methodology-bleed text that the TOC
        # anchor's body would have absorbed pre-fix.
        self.assertNotIn(
            "Synthetic methodology text",
            by_idx[3].description,
            "L-03 absorbed methodology bleed - TOC anchor filter regressed",
        )

    # ------------------------------------------------------------------
    # End-to-end: compact 2-findings-per-page PDF.
    # ------------------------------------------------------------------

    def test_compact_two_findings_pdf_yields_two_findings(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_compact_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 2)
        codes = sorted([f.severity_code for f in findings])
        self.assertEqual(codes, ["L", "M"])
        # Both have substantive descriptions via fallback.
        for f in findings:
            self.assertGreater(len(f.description), 50)
            self.assertGreaterEqual(f.parser_confidence, 0.65)

    # ------------------------------------------------------------------
    # Backward compatibility: standard single-finding-per-page layout
    # with explicit Description headers continues to work.
    # ------------------------------------------------------------------

    def test_standard_two_findings_still_works_with_description_headers(self) -> None:
        """The pashov_two_findings.pdf fixture (Description header form) must
        keep yielding the same 2 findings with NO compact-layout warning -
        we only fall back when the section_after_header pass returns empty."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertNotIn(
                "pashov-compact-layout-description-fallback",
                f.parser_warnings,
                f"compact-layout fallback fired incorrectly on standard layout: "
                f"{f.title!r}",
            )

    def test_critical_with_poc_still_works(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_critical_with_poc.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        # PoC subsection survives (regression for backward compat).
        self.assertIn("setFeeRecipient(mallory)", findings[0].proof_of_concept)

    def test_legacy_numeric_fallback_still_works(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_legacy_numeric.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 2)
        # No compact-layout anchor filter triggered on the fallback path
        # (we skip the filter when used_fallback is True).
        for f in findings:
            self.assertNotIn(
                "pashov-compact-layout-anchor-filtered",
                f.parser_warnings,
            )

    # ------------------------------------------------------------------
    # Edge cases.
    # ------------------------------------------------------------------

    def test_empty_pdf_handled_gracefully(self) -> None:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import LETTER

        tmp = Path(tempfile.mkdtemp(prefix="pashov_compact_empty_"))
        try:
            pdf_path = tmp / "empty.pdf"
            c = canvas.Canvas(str(pdf_path), pagesize=LETTER)
            c.drawString(72, 720, "Pashov Audit Group")
            c.drawString(72, 700, "Empty report")
            c.showPage()
            c.save()
            result = pdf_finding_extractor.extract_structured_pages(pdf_path)
            findings = pdf_finding_extractor.extract_pashov_findings(result)
            self.assertEqual(findings, [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_filter_conservative_when_no_body_anchor_exists(self) -> None:
        """If a (code, idx) group has ONLY TOC/summary anchors (no body
        anchor), the filter MUST keep them. Otherwise we silently drop
        findings whose body text was unrecognised."""
        # Build a synthetic anchor set manually:
        #   [L-01] TOC entry (page-number trailer)
        #   [L-02] body entry (clean)
        # Group (L, 01) has only TOC -> kept. Group (L, 02) has body -> kept.
        full_text = (
            "[L-01] Trailing only TOC anchor 5\n"
            "Some absorbed text after the TOC.\n"
            "[L-02] Real body anchor with no trailer\n"
            "Real body prose here that should be the description.\n"
        )
        bracket_re = pdf_finding_extractor._PASHOV_TITLE_RE
        matches = list(bracket_re.finditer(full_text))
        self.assertEqual(len(matches), 2)
        codes = [m.group(1) for m in matches]
        indices = [m.group(2) for m in matches]
        titles = [m.group(3).strip() for m in matches]
        (
            kept_matches,
            kept_codes,
            kept_indices,
            kept_titles,
            filtered,
        ) = pdf_finding_extractor._pashov_filter_compact_layout_anchors(
            matches, codes, indices, titles
        )
        # No drop: each group has only one anchor and the TOC-only group
        # has no body sibling to fall back to.
        self.assertEqual(len(kept_matches), 2)
        self.assertFalse(filtered)


if __name__ == "__main__":
    unittest.main()
