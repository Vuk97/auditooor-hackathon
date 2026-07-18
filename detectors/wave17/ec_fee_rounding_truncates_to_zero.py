"""
ec-fee-rounding-truncates-to-zero — generated from reference/patterns.dsl/ec-fee-rounding-truncates-to-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-fee-rounding-truncates-to-zero.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcFeeRoundingTruncatesToZero(AbstractDetector):
    ARGUMENT = "ec-fee-rounding-truncates-to-zero"
    HELP = "Fee computed as amount*rate/denominator truncates to zero for small amounts; attacker splits operations to avoid all fees."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-fee-rounding-truncates-to-zero.yaml"
    WIKI_TITLE = "Fee truncation to zero — no minimum-amount guard on fee computation"
    WIKI_DESCRIPTION = "The protocol computes a fee as `fee = amount * feeRate / FEE_DENOMINATOR`. For small amounts where `amount * feeRate < FEE_DENOMINATOR`, integer division rounds the fee to zero. An attacker performing many small operations pays no fees at all, while larger users pay the full rate — fee bypass by splitting."
    WIKI_EXPLOIT_SCENARIO = "Swap fee is 30 bps (0.3%). FEE_DENOMINATOR = 10000. Any swap with amount < 10000/30 = 333 tokens pays zero fee. Attacker routes 1M tokens as 3001 separate swaps of 333 tokens each, paying zero fee total versus paying 3000 tokens on a single swap."
    WIKI_RECOMMENDATION = "Either enforce a minimum operation amount (`require(amount >= MIN_AMOUNT)`) or add a minimum fee floor: `fee = max(1, amount * feeRate / FEE_DENOMINATOR)`. Alternatively, accumulate sub-wei fees in a running accumulator and only finalize transfers above a threshold."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'fee|Fee|basisPoint|BASIS_POINTS|protocolFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'fee\\s*=\\s*\\w+\\s*\\*\\s*\\w+\\s*/\\s*(10000|1000|100|FEE_DENOMINATOR|BASIS_POINTS)'}, {'function.body_not_contains_regex': 'require\\s*\\(.*fee\\s*>=?\\s*[1-9]|fee\\s*==\\s*0.*revert|minFee|MIN_FEE|dust'}, {'function.body_not_contains_regex': 'require\\s*\\(.*amount\\s*>=|MIN_AMOUNT|minAmount'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-fee-rounding-truncates-to-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
