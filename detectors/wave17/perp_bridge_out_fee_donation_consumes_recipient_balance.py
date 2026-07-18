"""
perp-bridge-out-fee-donation-consumes-recipient-balance

Row-local manual repair. The generated matcher was too broad for honest
closure. This detector stays intentionally narrow and only proves the owned
fixture-smoke/source shape:

1. a bridge-out helper or executeDeposit-style function has both `account` and
   `receiver` in scope,
2. it calls a `bridgeOut...` helper with `receiver` (or `deposit.receiver()`)
   passed into the fee-paying bridge account slot, and
3. there is no visible `account != receiver` guard that disables automatic
   bridge-out for third-party recipients.

Submission posture: NOT_SUBMIT_READY. This is fixture-smoke/source-shape
evidence only until broader corpus-backed validation exists.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ENTRYPOINT_RE = re.compile(
    r"(?i)(?:bridgeOutFromController|_bridgeOut|executeDeposit|executeGlvDeposit|_processBridgeOut)"
)
_BRIDGE_RE = re.compile(r"(?i)\bbridgeOut(?:FromController)?\s*\(")
_ACCOUNT_RECEIVER_SCOPE_RE = re.compile(
    r"(?is)\baccount\b.*\breceiver\b|\breceiver\b.*\baccount\b"
)
_FEE_PAYER_RECEIVER_RE = re.compile(
    r"(?is)\bbridgeOut(?:FromController)?\s*\([^;{}]*\b(?:deposit\s*\.\s*receiver\s*\(\s*\)|receiver)\b"
    r"[^;{}]*,\s*\b(?:deposit\s*\.\s*receiver\s*\(\s*\)|receiver)\b[^;{}]*\)"
)
_MINT_TO_RECEIVER_RE = re.compile(
    r"(?is)\b(?:mint|_mint|mintMarketTokens)\s*\([^;{}]*\b(?:deposit\s*\.\s*receiver\s*\(\s*\)|receiver)\b"
)
_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:multichainBalance|fee|wnt|bridgeFee|executionFee|fee-paying|fee paying)\b"
)
_GUARD_RE = re.compile(
    r"(?is)\bif\s*\(\s*account\s*!=\s*(?:deposit\s*\.\s*receiver\s*\(\s*\)|receiver)\s*\)\s*(?:return|{[^{}]*return;)"
    r"|\brequire\s*\(\s*account\s*==\s*(?:deposit\s*\.\s*receiver\s*\(\s*\)|receiver)\b"
)
_SAFE_ACCOUNT_BRIDGE_RE = re.compile(
    r"(?is)\bbridgeOut(?:FromController)?\s*\([^;{}]*\baccount\b[^;{}]*,\s*\baccount\b[^;{}]*\)"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_recipient_fee_donation_shape(function_src: str, contract_src: str) -> bool:
    if not _BRIDGE_RE.search(function_src):
        return False
    if not _ACCOUNT_RECEIVER_SCOPE_RE.search(function_src):
        return False
    if not _FEE_PAYER_RECEIVER_RE.search(function_src):
        return False
    if _GUARD_RE.search(function_src):
        return False
    if _SAFE_ACCOUNT_BRIDGE_RE.search(function_src):
        return False
    if not (_MINT_TO_RECEIVER_RE.search(function_src) or _FEE_CONTEXT_RE.search(function_src) or _FEE_CONTEXT_RE.search(contract_src)):
        return False
    return True


class PerpBridgeOutFeeDonationConsumesRecipientBalance(AbstractDetector):
    ARGUMENT = "perp-bridge-out-fee-donation-consumes-recipient-balance"
    HELP = (
        "Bridge-out helper charges fee against the recipient-side multichain "
        "bridge account, so a third party can donate dust and consume the "
        "recipient's WNT balance."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "perp-bridge-out-fee-donation-consumes-recipient-balance.yaml"
    )
    WIKI_TITLE = "Bridge-out charges fee to recipient multichain balance"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row "
        "flags a bridge-out helper or executeDeposit-style function that keeps "
        "`account` and `receiver` separate, then still passes `receiver` as the "
        "fee-paying bridge account without an `account != receiver` stop-guard."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker funds a dust deposit with `account=attacker` and "
        "`receiver=victim`. If execution auto-bridges the newly minted GM/GLV "
        "while charging the bridge fee to `receiver`, the victim's multichain "
        "WNT balance is consumed for an unwanted transfer."
    )
    WIKI_RECOMMENDATION = (
        "Do not auto-bridge when `account != receiver`, or always charge the "
        "bridge fee to `account`. Keep this row NOT_SUBMIT_READY until the "
        "shape is validated beyond the owned fixture pair."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_src = _source(contract)
            if "bridgeOut" not in contract_src:
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"public", "external", "internal"}:
                    continue
                if not _ENTRYPOINT_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not _has_recipient_fee_donation_shape(function_src, contract_src):
                    continue

                info = [
                    function,
                    (
                        " auto-bridges with `receiver` as the fee-paying bridge "
                        "account and no visible `account != receiver` guard. "
                        "NOT_SUBMIT_READY: fixture-smoke/source-shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
