"""
protocol-fee-withdraw-no-claimed-flag - generated from reference/patterns.dsl/protocol-fee-withdraw-no-claimed-flag.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py protocol-fee-withdraw-no-claimed-flag.yaml
Source: solodit-cluster-C0021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ProtocolFeeWithdrawNoClaimedFlag(AbstractDetector):
    ARGUMENT = "protocol-fee-withdraw-no-claimed-flag"
    HELP = "Privileged fee-withdraw function transfers the accumulator balance without zeroing the accumulator or setting a claimed flag, letting the operator call it repeatedly and drain the same fees multiple times."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/protocol-fee-withdraw-no-claimed-flag.yaml"
    WIKI_TITLE = "Protocol fee withdraw missing claimed flag / accumulator reset"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves the narrow fee-withdraw shape where a public withdraw path reads a protocol-fee accumulator into a local amount, transfers that amount out, and never writes the accumulator back in the same function. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A treasury owner calls `withdrawFee()` which snapshots `fee = accruedFee` and transfers `fee` to the treasury. Because the function never clears or decrements `accruedFee`, the same owner can call `withdrawFee()` again and receive the same stale fee balance a second time."
    WIKI_RECOMMENDATION = "Zero, delete, or decrement the fee accumulator before the transfer, or set a one-shot claimed flag for the same accounting slot. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(protocolFee|accruedFee|feeBalance|accumulatedFees|feesCollected|_fees)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdrawFee|withdrawFees|withdrawProtocolFee|claimFees|collectFees|sweepFees|harvestFees|retrieveFees)[A-Za-z]*$'}, {'function.body_contains_regex': '(safeTransfer|transfer|\\.call\\s*\\{\\s*value)\\s*\\('}, {'function.reads_state_var_matching_regex': '(protocolFee|accruedFee|feeBalance|accumulatedFees|feesCollected|_fees)'}, {'function.body_contains_regex': '\\b(?:uint(?:256)?\\s+)?[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*(protocolFee|accruedFee|feeBalance|accumulatedFees|feesCollected|_fees)\\b'}, {'function.body_not_contains_regex': '((protocolFee|accruedFee|feeBalance|accumulatedFees|feesCollected|_fees)\\s*(\\[[^\\]]+\\])?\\s*([+\\-*/%]?=|\\+\\+|--)|delete\\s+(protocolFee|accruedFee|feeBalance|accumulatedFees|feesCollected|_fees)|feesClaimed\\s*=\\s*true|claimed\\s*\\[[^\\]]+\\]\\s*=\\s*true|hasClaimed\\s*\\[)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - protocol-fee-withdraw-no-claimed-flag: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
