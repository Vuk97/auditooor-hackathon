"""
dos-cap-block-or-factory-growth-unbounded.

Hand-written recall detector for two same-class dos-cap-weakening samples:
block.gaslimit refund math and non-idempotent createPair flows.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class DosCapBlockOrFactoryGrowthUnbounded(AbstractDetector):
    ARGUMENT = "dos-cap-block-or-factory-growth-unbounded"
    HELP = (
        "NOT_SUBMIT_READY detector recall only: flags block.gaslimit refund payouts "
        "and unconditional createPair calls without an existing-pair fallback."
    )
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "dos-cap-block-or-factory-growth-unbounded.yaml"
    )
    WIKI_TITLE = "DoS cap weakening through block gaslimit refund or non-idempotent pair creation"
    WIKI_DESCRIPTION = (
        "Detector recall only. A per-transaction refund path should not price "
        "reimbursement from block.gaslimit, and a factory growth path should be "
        "idempotent when the pair already exists."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A relayer overpays refunds from a block-wide gas limit, or a launch "
        "flow is blocked when an attacker creates the expected pair first."
    )
    WIKI_RECOMMENDATION = (
        "Use measured gas deltas with a max refund, and check getPair or pairFor "
        "before createPair or recover through try/catch."
    )

    _CONTRACT_SURFACE_RE = re.compile(
        r"block\.gaslimit|createPair|IUniswapV2Factory|factory",
        re.IGNORECASE,
    )
    _BLOCK_GAS_REFUND_RE = re.compile(
        r"block\.gaslimit[\s\S]{0,180}(tx\.gasprice|gasprice|refund|reimburs)"
        r"|refund[\s\S]{0,180}block\.gaslimit",
        re.IGNORECASE,
    )
    _VALUE_PAYOUT_RE = re.compile(
        r"\.call\s*\{\s*value\s*:|\.transfer\s*\(|\.send\s*\(",
        re.IGNORECASE,
    )
    _REFUND_CONTEXT_RE = re.compile(
        r"refund|reimburs|relay|keeper|gas",
        re.IGNORECASE,
    )
    _CREATE_PAIR_RE = re.compile(r"\.\s*createPair\s*\(", re.IGNORECASE)
    _PAIR_CONTEXT_RE = re.compile(r"launch|create|factory|pair|token", re.IGNORECASE)
    _PAIR_GUARD_RE = re.compile(
        r"getPair\s*\(|pairFor\s*\(|try\s+[^;{]*\.createPair|catch\s*\("
        r"|existingPair|pair\s*!=\s*address\s*\(\s*0\s*\)",
        re.IGNORECASE,
    )

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    @classmethod
    def _matches_block_gas_refund(cls, src: str) -> bool:
        return (
            bool(cls._BLOCK_GAS_REFUND_RE.search(src))
            and bool(cls._VALUE_PAYOUT_RE.search(src))
            and bool(cls._REFUND_CONTEXT_RE.search(src))
        )

    @classmethod
    def _matches_create_pair_without_fallback(cls, src: str) -> bool:
        return (
            bool(cls._CREATE_PAIR_RE.search(src))
            and bool(cls._PAIR_CONTEXT_RE.search(src))
            and not bool(cls._PAIR_GUARD_RE.search(src))
        )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_src = _source(contract)
            if not self._CONTRACT_SURFACE_RE.search(contract_src):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                src = _source(function)
                if self._matches_block_gas_refund(src):
                    reason = "block.gaslimit refund payout"
                elif self._matches_create_pair_without_fallback(src):
                    reason = "createPair without existing-pair fallback"
                else:
                    continue
                info = [
                    function,
                    f" - {self.ARGUMENT}: {reason}. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
