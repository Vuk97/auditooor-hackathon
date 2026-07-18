"""Hermetic Pashov-style PDF fixture builder for W2.4 Phase-1 tests.

Generates small synthetic PDFs that mimic the Pashov audit-report
layout: bracketed severity-coded finding IDs (``[H-1]`` / ``[M-2]`` /
``[L-3]`` / ``[C-1]`` / ``[I-1]``) followed by Markdown-ish
``Description`` / ``Recommendation`` / optionally ``Proof of Concept``
subsections. A fourth fallback fixture exercises the pre-2024 Pashov
template (numeric ``1. Title`` headings + body ``Severity:`` label).

The point is to verify the Pashov parser against a structure we fully
control - real Pashov PDFs are pulled by the live driver only.

This module is invoked by the test suite on import to materialise the
fixture PDFs into ``audit_firm_pdf_samples/pashov/`` if they are
missing. It depends on ``reportlab`` (already a Hackerman test
dependency for synthetic-corpus generation).

Kept separate from ``_fixture_builder.py`` (ToB builder) and
``_sherlock_fixture_builder.py`` (Sherlock builder) so the three parser
variants can evolve independently without merge-pain.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "pashov"


def _build_pdf(out_path: Path, lines: Iterable[str]) -> None:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import LETTER

    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=LETTER)
    width, height = LETTER
    y = height - 72
    line_height = 14
    text_obj = c.beginText(72, y)
    text_obj.setFont("Helvetica", 11)
    for line in lines:
        # Page-break when y drops below 72.
        if text_obj.getY() < 72:
            c.drawText(text_obj)
            c.showPage()
            text_obj = c.beginText(72, height - 72)
            text_obj.setFont("Helvetica", 11)
        text_obj.textLine(line)
    c.drawText(text_obj)
    c.showPage()
    c.save()


def _sample_pashov_two_findings_high_medium() -> List[str]:
    """Modern Pashov template, 2 findings (one High, one Medium).

    The High finding carries a ``Proof of Concept`` subsection (matches
    the ~40 % prevalence quoted in the spec). The Medium finding does
    not, so the parser must handle both paths in a single PDF.
    """
    return [
        "Pashov Audit Group",
        "Security Review: Sample Vault",
        "Date: 2024-10-12",
        "",
        "Executive Summary",
        "This is a synthetic Pashov-style audit report used for testing.",
        "",
        "Findings",
        "",
        "[H-1] Reentrancy in withdraw allows fund theft",
        "",
        "Description",
        "The withdraw function in target/contracts/Vault.sol:L42-L60 calls",
        "an external token before updating internal accounting state. An",
        "attacker can re-enter withdraw and drain the vault.",
        "",
        "Proof of Concept",
        "Alice deposits 100 tokens. Alice deploys a malicious token whose",
        "transfer hook calls back into withdraw before the balance update",
        "in target/contracts/Vault.sol:L55. The re-entry drains the vault.",
        "",
        "Recommendation",
        "Apply the checks-effects-interactions pattern: update internal",
        "balances before the external token call. Consider adding a",
        "non-reentrancy modifier to the withdraw function.",
        "",
        "[M-2] Integer overflow in fee calculation results in loss",
        "",
        "Description",
        "The fee calculation in target/contracts/Fee.sol:L100 multiplies",
        "two unchecked uint256 values which can overflow for large inputs.",
        "",
        "Recommendation",
        "Use Solidity 0.8+ checked arithmetic or SafeMath for the fee",
        "calculation. Add unit tests covering the boundary cases.",
        "",
    ]


def _sample_pashov_critical_with_poc() -> List[str]:
    """Modern Pashov template, 1 Critical finding with PoC subsection."""
    return [
        "Pashov Audit Group",
        "Security Review: Sample AMM",
        "",
        "[C-1] Missing access control on admin setter",
        "",
        "Description",
        "The setFeeRecipient function in target/contracts/AMM.sol:L88 has",
        "no onlyOwner guard. Any caller can redirect the protocol fee",
        "stream to an attacker-controlled address.",
        "",
        "Proof of Concept",
        "Mallory calls AMM.setFeeRecipient(mallory) at target/contracts/AMM.sol:L88.",
        "All subsequent protocol fees route to Mallory's address. No revert.",
        "",
        "Recommendation",
        "Add an onlyOwner modifier to setFeeRecipient. Confirm via tests.",
        "",
    ]


def _sample_pashov_low_informational_no_findings() -> List[str]:
    """Modern Pashov template with no security findings.

    Two ``[I-1]`` and ``[L-1]`` informational/low rows DO appear in
    the body to exercise the lower severity mapping AND a true
    no-findings PDF would just contain narrative text. This fixture
    splits the difference: it carries Info + Low rows so the parser
    proves the C/H/M/L/I mapping is exhaustive.
    """
    return [
        "Pashov Audit Group",
        "Security Review: Sample Bridge",
        "",
        "[L-1] Inconsistent error handling across deposit paths",
        "",
        "Description",
        "The deposit paths in target/contracts/Bridge.sol:L20 and",
        "target/contracts/Bridge.sol:L75 use inconsistent error revert",
        "messages and event signatures.",
        "",
        "Recommendation",
        "Standardise error messages and event signatures across all",
        "deposit code paths.",
        "",
        "[I-1] Gas optimisation: cache storage reads in claim loop",
        "",
        "Description",
        "The claim loop in target/contracts/Bridge.sol:L150 re-reads the",
        "deposit mapping per iteration. Caching the read in a local would",
        "save ~200 gas per claim.",
        "",
        "Recommendation",
        "Cache deposits[claimId] in a memory local before the loop body.",
        "",
    ]


# R36 citation: pathspec for LANE-195-PDF-EXTRACTOR-COMPACT registered via
# tools/agent-pathspec-register.py; this file declared in
# .auditooor/agent_pathspec.json.


def _sample_pashov_compact_three_findings_no_desc_header() -> List[str]:
    """Compact-layout Pashov PDF (Task #195).

    Mirrors the DefiApp 2026-05-23 layout: each [L-NN] bracketed
    heading is followed DIRECTLY by the finding's prose (no
    ``Description``/``Recommendation`` headers). The same bracketed
    title appears 3 times - once in the TOC (with trailing page
    number), once in the summary-of-findings table (with trailing
    severity + status word pair), and once at the actual body. The
    extractor must drop the TOC + summary anchors so the real body
    wins dedup, and must fall back to body-as-description when no
    ``Description:`` header is present.
    """
    return [
        "Pashov Audit Group",
        "Sample-Compact Security Review",
        "May 23rd 2026",
        "",
        "Contents",
        "1. About Pashov Audit Group 3",
        "2. Disclaimer 3",
        "3. Risk Classification 3",
        "4. Methodology 4",
        "5. Findings 6",
        "Low findings 7",
        "[L-01] First compact finding without description header 7",
        "[L-02] Second compact finding inline rec phrasing 7",
        "[L-03] Third compact finding suggested phrasing 7",
        "Pashov Audit Group Sample-Compact Security Review",
        "2 / 8",
        "",
        "1. About Pashov Audit Group",
        "Pashov Audit Group is a synthetic audit firm used only for unit tests.",
        "This paragraph fills the about section so the TOC anchor's body",
        "extends across the about / disclaimer / methodology pages.",
        "Pashov Audit Group Sample-Compact Security Review",
        "3 / 8",
        "",
        "2. Disclaimer",
        "Synthetic disclaimer.",
        "",
        "3. Risk Classification",
        "Severity scale: Critical / High / Medium / Low / Informational.",
        "",
        "4. Methodology",
        "Synthetic methodology text intended to bleed into the TOC anchor body",
        "if the extractor does not filter TOC anchors. The methodology mentions",
        "Recommendation steps and Description tracking which would otherwise",
        "trigger the section-signal scorer.",
        "Pashov Audit Group Sample-Compact Security Review",
        "4 / 8",
        "",
        "5. Findings",
        "Findings count",
        "Severity Amount",
        "Low 3",
        "Total findings 3",
        "Summary of findings",
        "ID Title Severity Status",
        "[L-01] First compact finding without description header Low Acknowledged",
        "[L-02] Second compact finding inline rec phrasing Low Acknowledged",
        "[L-03] Third compact finding suggested phrasing Low Acknowledged",
        "Pashov Audit Group Sample-Compact Security Review",
        "5 / 8",
        "",
        "Low findings",
        "[L-01] First compact finding without description header",
        "The contract at target/contracts/Compact.sol:L42 includes a parameter",
        "called fooBar that is not documented in the README, leading to confusion",
        "about its intended use across teams. The same parameter appears in the",
        "deployment config and is wired to a privileged setter without a",
        "comment.",
        "It is recommended to document the fooBar parameter in the README.",
        "",
        "[L-02] Second compact finding inline rec phrasing",
        "The error code emitted at target/contracts/Compact.sol:L88 mixes",
        "natural-language strings with numeric codes which complicates",
        "off-chain observability. The off-chain monitor cannot reliably",
        "branch on either form.",
        "It's recommended to standardise on a single numeric error code scheme.",
        "",
        "[L-03] Third compact finding suggested phrasing",
        "The fee router at target/contracts/Compact.sol:L150 reuses the same",
        "storage slot across two unrelated config groups. A future migration",
        "could overwrite one group accidentally.",
        "It's suggested to split the storage layout into two separate slots so",
        "the migration path stays unambiguous.",
        "Pashov Audit Group Sample-Compact Security Review",
        "6 / 8",
        "",
    ]


def _sample_pashov_compact_two_findings_no_desc_header() -> List[str]:
    """Compact-layout Pashov PDF with exactly 2 findings (N=2 variant).

    Same shape as the 3-findings fixture but with N=2 so the parser is
    exercised on the smaller compact layout that some Pashov PDFs use
    when a project has a tight findings count.
    """
    return [
        "Pashov Audit Group",
        "Sample-Compact-Two Security Review",
        "",
        "Contents",
        "[M-01] First compact medium finding 5",
        "[L-01] Trailing low finding 5",
        "Pashov Audit Group Sample-Compact-Two Security Review",
        "2 / 6",
        "",
        "1. Methodology",
        "Synthetic body to bleed methodology into TOC anchor body if the",
        "extractor fails to filter the TOC anchor.",
        "Pashov Audit Group Sample-Compact-Two Security Review",
        "3 / 6",
        "",
        "Summary of findings",
        "ID Title Severity Status",
        "[M-01] First compact medium finding Medium Fixed",
        "[L-01] Trailing low finding Low Acknowledged",
        "Pashov Audit Group Sample-Compact-Two Security Review",
        "4 / 6",
        "",
        "Findings",
        "[M-01] First compact medium finding",
        "The setter in target/contracts/CompactTwo.sol:L20 is missing a zero",
        "address guard which can lock the contract permanently if invoked",
        "by an automated migration tool.",
        "It is recommended to add a require(newOwner != address(0)) at the top",
        "of the setter.",
        "",
        "[L-01] Trailing low finding",
        "The event emitted in target/contracts/CompactTwo.sol:L60 packs three",
        "indexed parameters where two would suffice for analytics indexing.",
        "Consider dropping the third indexed parameter to save gas.",
        "",
    ]


def _sample_pashov_legacy_numeric_template() -> List[str]:
    """Pre-2024 Pashov template: numeric headings + body ``Severity:`` label.

    Exercises the fallback parser path. Severity must be recovered
    from the body label rather than from a bracketed-heading prefix.
    """
    return [
        "Pashov Audit Group",
        "Security Review: Legacy Project",
        "Date: 2023-06-04",
        "",
        "1. Unsafe ERC20 transfer without return-value check",
        "",
        "Severity: High",
        "",
        "Description",
        "The transfer call in target/contracts/Legacy.sol:L210 does not",
        "check the boolean return value. Some non-standard ERC20 tokens",
        "silently fail without reverting, leaving accounting desynced.",
        "",
        "Recommendation",
        "Use OpenZeppelin's SafeERC20 wrapper to enforce a revert on a",
        "false return value.",
        "",
        "2. Missing zero-address check on owner setter",
        "",
        "Severity: Low",
        "",
        "Description",
        "The setOwner function in target/contracts/Legacy.sol:L88 does",
        "not validate the new-owner argument against the zero address.",
        "Misconfiguration can permanently lock owner-gated functionality.",
        "",
        "Recommendation",
        "Add a require(newOwner != address(0)) check at the top of",
        "setOwner.",
        "",
    ]


# R36 citation: pathspec via tools/agent-pathspec-register.py (see header).
_FIXTURES = {
    "pashov_two_findings.pdf": _sample_pashov_two_findings_high_medium,
    "pashov_critical_with_poc.pdf": _sample_pashov_critical_with_poc,
    "pashov_low_informational.pdf": _sample_pashov_low_informational_no_findings,
    "pashov_legacy_numeric.pdf": _sample_pashov_legacy_numeric_template,
    "pashov_compact_three_findings.pdf": _sample_pashov_compact_three_findings_no_desc_header,
    "pashov_compact_two_findings.pdf": _sample_pashov_compact_two_findings_no_desc_header,
}


def ensure_fixtures() -> dict:
    """Materialise the fixture PDFs on disk if missing; return path map."""
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
