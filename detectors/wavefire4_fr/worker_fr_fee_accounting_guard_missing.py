"""
worker-fr-fee-accounting-guard-missing - generated from reference/patterns.dsl/worker-fr-fee-accounting-guard-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py worker-fr-fee-accounting-guard-missing.yaml
Source: auditooor-worker-fr-fire4-20260604
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WorkerFrFeeAccountingGuardMissing(AbstractDetector):
    ARGUMENT = "worker-fr-fee-accounting-guard-missing"
    HELP = "Fee-dependent entry point uses fee state without the matching guard: subtract fee float from reserves, accrue before rate changes or charges, or enforce protocol fee receiver and max-share bounds."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/worker-fr-fee-accounting-guard-missing.yaml"
    WIKI_TITLE = "Fee accounting guard missing before fee-dependent pricing"
    WIKI_DESCRIPTION = "This detector is a bounded fee-redirect class lift over three confirmed fixture families. It flags fee-dependent functions that use raw AMM reserves while a fee accumulator exists, change or charge fees while an accrual helper exists but is not called, or return protocol fee share from config without zero-receiver and max-share guards."
    WIKI_EXPLOIT_SCENARIO = "A user burns or swaps against reserves that still include protocol fee float, a rate setter silently re-prices old-period fees by skipping accrual, or a protocolFeeShare() view returns a misconfigured share that burns or over-routes protocol revenue."
    WIKI_RECOMMENDATION = "Before fee-dependent pricing, isolate or materialize the fee state. Subtract accrued fees from reserve math, call the accrual helper before changing rates or charging fees, and guard protocol fee share with zero-receiver and max-share checks."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(accruedFee|accumulatedFee|launchpadFee|protocolFee|treasuryFee|feePerSecond|lastFeeCollected|protocolFeeConfig|protocolFeeShare|MAX_PROTOCOL_FEE_SHARE|CONFIG_SCALE)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(mint|burn|swap|_mint|_burn|setFee|changeFee|setRate|configureFee|chargeFee|collectFees|updateFeeRate|setFeePerSecond|setFeePerShare|protocolFeeShare)$'}, {'function.body_contains_regex': '(?is)(?:\\b(?:reserve0|reserve1|_reserve0|_reserve1)\\b|balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|IERC20\\s*\\(\\s*\\w+\\s*\\)\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|\\b(?:feePerSecond|feeRate|feePerShare)\\s*=|\\b(?:accumulatedFees|accruedFees|feesAccrued)\\s*(?:\\+=|=)|protocolFeeConfig|protocolShare|feeConfig)'}, {'function.body_not_contains_regex': '(?is)(?:\\b(?:realReserve|subFees|_subtractFee)\\b|\\b(?:reserve0|reserve1|_reserve0|_reserve1|bal\\w*)\\s*-\\s*(?:accruedFee|accruedFees|accumulatedFee|accumulatedFees|launchpadFee|protocolFee|treasuryFee)\\b|(?:accrueFee|_accrue|updateFee|collectFee)\\s*\\(|feeReceiver\\s*==\\s*address\\s*\\(\\s*0\\s*\\)|protocolShare\\s*>\\s*MAX_PROTOCOL_FEE_SHARE|MAX_PROTOCOL_FEE_SHARE)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" - worker-fr-fee-accounting-guard-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
