"""
imm-curation-tax-rounds-to-zero — generated from reference/patterns.dsl/imm-curation-tax-rounds-to-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-curation-tax-rounds-to-zero.yaml
Source: immunefi/the-graph-rounding-error
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmCurationTaxRoundsToZero(AbstractDetector):
    ARGUMENT = "imm-curation-tax-rounds-to-zero"
    HELP = "Curation / protocol fee computed as `amount * taxBps / 10000` rounds to zero for small amounts. On cheap L2s attackers batch sub-denominator mints and pay no tax. Fix: compute net = amount * (DENOM - taxBps) / DENOM and derive fee = amount - net."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-curation-tax-rounds-to-zero.yaml"
    WIKI_TITLE = "Percentage fee rounds to zero for small inputs (The Graph L2Curation pattern)"
    WIKI_DESCRIPTION = "Fee math of the form `fee = amount * feeBps / DENOM` followed by `net = amount - fee` truncates `fee` to zero whenever `amount * feeBps < DENOM`. This is the standard Solidity integer-division gotcha. On L1 the gas cost of a single mint dwarfs the saved fee, so the rounding error is usually ignorable; on cheap L2s the economic friction disappears and the bug becomes exploitable by batching sub-thr"
    WIKI_EXPLOIT_SCENARIO = "The Graph (Jan 2024): `Curation.mint(tokensIn)` applied a 1% curation tax computed as `tax = tokensIn * 100 / 10000`. For `tokensIn < 100` the tax is zero. Attacker on Arbitrum mints 99 tokens at a time, thousands of calls per block, accumulating a signal position without paying any tax. Cumulative fee loss scaled with protocol TVL; full bounty $290,497 covered this and a second rounding defect in"
    WIKI_RECOMMENDATION = "Invert the math: `tokensAfterTax = tokensIn * (DENOM - taxBps) / DENOM; tax = tokensIn - tokensAfterTax;`. Alternatively use `Math.mulDiv` with `Rounding.Ceil` on the fee path. Add an explicit `require(tax > 0 || amount == 0, \"dust\");` to reject sub-unit transfers. Audit every protocol fee that us"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'curationTax|curation_tax|MAX_PPM|BASIS_POINTS|BPS_DENOMINATOR|\\b10000\\b|\\b1000000\\b'}, {'contract.source_matches_regex': 'mint\\s*\\(|tokensToSignal|_calculateFee|_computeFee'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(tokensToSignal|_tokensToSignal|calculateFee|_calculateFee|_applyCurationTax|_chargeTax|_computeFee)$'}, {'function.body_contains_regex': '(\\*\\s*curationTax|\\*\\s*taxBps|\\*\\s*feeBps|\\*\\s*tax\\b).*(/\\s*(10000|1000000|MAX_PPM|BASIS_POINTS|BPS_DENOMINATOR|DENOM))'}, {'function.body_not_contains_regex': '\\(\\s*(10000|1000000|MAX_PPM|BASIS_POINTS|BPS_DENOMINATOR|DENOM)\\s*-\\s*(curationTax|taxBps|feeBps|tax)|mulDivRoundingUp|roundingUp|Math\\.ceilDiv'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-curation-tax-rounds-to-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
