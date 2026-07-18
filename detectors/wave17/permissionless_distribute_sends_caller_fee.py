"""
Permissionless distribute sends caller fee.

Row-local repair only. This detector intentionally stays narrow and proves just
the owned fixture shape: a public/external `distribute` entrypoint with no
visible caller authorization that transfers a royalty/keeper/caller fee
directly to `msg.sender`.

Submission posture: NOT_SUBMIT_READY. The proof is fixture-smoke/source-shape
only and does not claim broad exploit coverage.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_DISTRIBUTE_NAME_RE = re.compile(r"^distribute$", re.IGNORECASE)
_FEE_NAME_RE = re.compile(
    r"\b(?:royaltyFee|royaltyfee|keeperFee|callerFee|callerReward|distributorFee)\b",
    re.IGNORECASE,
)
_CALLER_PAYOUT_RE = re.compile(
    r"(?:_msgSender\s*\(\s*\)|msg\.sender)\s*\.\s*safeTransferETH\s*\([^;]*"
    r"|payable\s*\(\s*msg\.sender\s*\)\s*\.\s*transfer\s*\([^;]*"
    r"|msg\.sender\s*\.\s*transfer\s*\([^;]*",
    re.IGNORECASE,
)
_AUTHZ_RE = re.compile(
    r"\b(?:onlyOwner|onlyRole|onlyKeeper|onlyAdmin|requiresAuth|auth|"
    r"require\s*\(\s*msg\.sender\s*==\s*(?:owner|keeper|admin|treasury)|"
    r"require\s*\(\s*_msgSender\s*\(\s*\)\s*==\s*(?:owner|keeper|admin|treasury))",
    re.IGNORECASE,
)
_REWARD_BUCKET_RE = re.compile(
    r"\b(?:royaltyFees|rewardPool|protocolFees|feesAccrued|pendingRewards)\b",
    re.IGNORECASE,
)


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class PermissionlessDistributeSendsCallerFee(AbstractDetector):
    ARGUMENT = "permissionless-distribute-sends-caller-fee"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags the "
        "owned `distribute` shape that pays a visible royalty/keeper/caller "
        "fee directly to `msg.sender` without a visible caller guard."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "permissionless-distribute-sends-caller-fee.yaml"
    )
    WIKI_TITLE = "Permissionless distribute pays a caller fee to msg.sender"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row proves only the owned "
        "`distribute(...)` shape where a public/external reward distribution "
        "entrypoint exposes a named royalty/keeper/caller fee and transfers "
        "that fee directly to `msg.sender` without a visible same-function "
        "caller authorization guard. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A protocol leaves `distribute(credId)` public so anyone can trigger "
        "accounting, but the same entrypoint pays `royaltyFee` or `callerFee` "
        "to `msg.sender`. A searcher repeatedly calls the function and skims "
        "the per-call fee intended for an operator."
    )
    WIKI_RECOMMENDATION = (
        "Either restrict the distribution entrypoint to an authorized keeper "
        "role, or send the incentive to a fixed treasury/keeper address "
        "instead of `msg.sender`. Keep this row NOT_SUBMIT_READY until corpus-"
        "backed exploit evidence exists beyond the owned fixture pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_text(contract)
            if not _REWARD_BUCKET_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if not _DISTRIBUTE_NAME_RE.search(getattr(function, "name", "") or ""):
                    continue

                source = _source_text(function)
                if not source:
                    continue
                if not _FEE_NAME_RE.search(source):
                    continue
                if not _CALLER_PAYOUT_RE.search(source):
                    continue
                if _AUTHZ_RE.search(source):
                    continue

                info = [
                    function,
                    " — permissionless-distribute-sends-caller-fee: visible "
                    "caller-fee payout to `msg.sender` in a public "
                    "`distribute` entrypoint with no same-function caller "
                    "guard. NOT_SUBMIT_READY: fixture-smoke/source-shape proof "
                    "only.",
                ]
                results.append(self.generate_result(info))
        return results
