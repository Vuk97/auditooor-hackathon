"""Hermetic SB Security-style PDF fixture builder for deep-mine tests.

Generates small synthetic PDFs that mimic the native SBSecurity report
layout: numbered finding headings (``5.1.1.Title``) grouped by severity,
followed by ``Severity:`` / ``Context:`` / ``Description:`` /
``Recommendation:`` / ``Resolution:`` fields.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "sb_security"


def _build_pdf(out_path: Path, lines: Iterable[str]) -> None:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import LETTER

    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=LETTER)
    _, height = LETTER
    text_obj = c.beginText(72, height - 72)
    text_obj.setFont("Helvetica", 11)
    for line in lines:
        if text_obj.getY() < 72:
            c.drawText(text_obj)
            c.showPage()
            text_obj = c.beginText(72, height - 72)
            text_obj.setFont("Helvetica", 11)
        text_obj.textLine(line)
    c.drawText(text_obj)
    c.showPage()
    c.save()


def _sample_native_two_findings() -> List[str]:
    return [
        "Sample Vault",
        "Security Review",
        "",
        "Contents",
        "5.Findings",
        "5.1.Critical severity",
        "5.1.1.withdrawFunds always uses target vault to withdraw instead to iterate ........ 6",
        "5.2.High severity",
        "5.2.1.Excess ETH is not refunded on mint ........ 10",
        "",
        "5.Findings",
        "5.1.Critical severity",
        "5.1.1.withdrawFunds always uses target vault to withdraw instead to iterate",
        "Severity: Critical Risk",
        "Context: RouterVaults.sol#L88",
        "Description: RouterVaults::withdrawFunds iterates over vaults in listVaults but unzap",
        "from the targetVault. This can revert when the target vault has insufficient reserves.",
        "Recommendation: Extract vaults from vaultSplit and unzap from each vault in order.",
        "Resolution: Fixed",
        "",
        "5.2.High severity",
        "5.2.1.Excess ETH is not refunded on mint",
        "Severity: High Risk",
        "Context: Crate721NTLC.sol#L120",
        "Description: The mint path accepts msg.value above the required price and keeps the excess.",
        "Recommendation: Refund msg.value - requiredPrice to msg.sender after minting.",
        "Resolution: Acknowledged",
        "",
    ]


def _sample_low_with_poc() -> List[str]:
    return [
        "Sample Router",
        "Security Review",
        "",
        "7 Findings",
        "7.1 Low Risk",
        "7.1.1 Loss of user funds due to unreturned leftover tokens in amount",
        "Description: The SwapRouter::_performSwap function fails to return unused input tokens.",
        "Impact: Users lose any portion of input tokens that are not consumed by the DEX swap.",
        "Proof of Concept: SwapHelper.sweep(tokenIn, positionSwapper) returns leftovers elsewhere.",
        "Recommended Mitigation: Implement deterministic post-swap cleanup and refund leftover tokenIn.",
        "Resolution: Acknowledged",
        "",
    ]


def _sample_bracket_ids_with_toc_duplicates() -> List[str]:
    return [
        "Sample Lending",
        "Security Review",
        "",
        "Table of Contents",
        "[C-01] Unchecked collateral withdrawal can drain reserves ........ 8",
        "[H-01] Liquidation accounting can double-count repaid debt ........ 12",
        "[M-01] Oracle heartbeat is not enforced ........ 16",
        "[L-01] Event omits recipient for queued withdrawals ........ 20",
        "[I-01] NatSpec uses stale parameter names ........ 24",
        "",
        "Findings",
        "[C-01] Unchecked collateral withdrawal can drain reserves",
        "Context: LendingPool.sol#L88",
        "Description: The withdrawCollateral path transfers collateral before reducing",
        "the borrower balance, allowing a reentrant reserve drain.",
        "Recommendation: Update collateral accounting before external transfers.",
        "Resolution: Fixed",
        "",
        "[H-01] Liquidation accounting can double-count repaid debt",
        "Context: Liquidator.sol#L144",
        "Description: Liquidation settlement applies repaid debt to both the isolated",
        "bucket and the global debt accumulator.",
        "Recommendation: Apply the debt delta exactly once and assert accumulator parity.",
        "Resolution: Acknowledged",
        "",
        "[M-01] Oracle heartbeat is not enforced",
        "Context: PriceOracle.sol#L52",
        "Description: The price reader accepts stale oracle rounds after heartbeat expiry.",
        "Recommendation: Reject prices older than the configured heartbeat.",
        "Resolution: Fixed",
        "",
        "[L-01] Event omits recipient for queued withdrawals",
        "Context: WithdrawalQueue.sol#L31",
        "Description: The queued withdrawal event omits the recipient address.",
        "Recommendation: Include the recipient in the emitted event.",
        "Resolution: Acknowledged",
        "",
        "[I-01] NatSpec uses stale parameter names",
        "Context: VaultDocs.sol#L12",
        "Description: The NatSpec comment references the previous receiver parameter name.",
        "Recommendation: Update the comment to match the current function signature.",
        "Resolution: Fixed",
        "",
    ]


def _sample_no_findings() -> List[str]:
    return [
        "SB Security",
        "Security Review",
        "",
        "Executive Summary",
        "No security findings were identified during this review.",
        "",
    ]


_FIXTURES = {
    "sb_security_native_two_findings.pdf": _sample_native_two_findings,
    "sb_security_low_with_poc.pdf": _sample_low_with_poc,
    "sb_security_bracket_ids_with_toc_duplicates.pdf": (
        _sample_bracket_ids_with_toc_duplicates
    ),
    "sb_security_no_findings.pdf": _sample_no_findings,
}


def ensure_fixtures() -> dict:
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
