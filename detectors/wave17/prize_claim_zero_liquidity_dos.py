"""
prize-claim-zero-liquidity-dos — generated from reference/patterns.dsl/prize-claim-zero-liquidity-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py prize-claim-zero-liquidity-dos.yaml
Source: solodit/C0103
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PrizeClaimZeroLiquidityDos(AbstractDetector):
    ARGUMENT = "prize-claim-zero-liquidity-dos"
    HELP = "Prize/reward claim function reads tier/prize liquidity without a zero-liquidity short-circuit, so winners hit a revert (div-by-zero or underflow) once the tier is drained and cannot claim their legitimate prize."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/prize-claim-zero-liquidity-dos.yaml"
    WIKI_TITLE = "Prize claim DoS when tier liquidity is zero"
    WIKI_DESCRIPTION = "PrizePool-style contracts compute per-winner payouts as a function of `tierLiquidity` or indexed `liquidity[tier]`. When the tier's liquidity reaches zero (either by prior claims or by design during an empty tier), unguarded division, indexing, or proportional math panic-reverts the entire claim path. All subsequent winners in that tier are DoS'd, losing their accrued prize."
    WIKI_EXPLOIT_SCENARIO = "A PrizePool distributes rewards across multiple tiers. After some winners claim, the last tier's `tierLiquidity` is drained to zero. The next winner invokes `claimPrize(tier=last)`. The function performs `fee = prize / tierLiquidity` (or equivalent math indexing `liquidity[tier]`) which panic-reverts with 0x12 (division-by-zero) or 0x11 (underflow). The caller's claim reverts; no fallback returns "
    WIKI_RECOMMENDATION = "Before performing any arithmetic or indexing on `tierLiquidity`, short-circuit: `if (tierLiquidity == 0) return 0;` (or `continue` in batch loops). Treat zero-liquidity as a valid terminal state, not a revert condition."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(prize|tier|reward|jackpot|winnings)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(claim|claimPrize|claimReward|getReward|redeem|payout|distributePrize|awardPrize)'}, {'function.body_contains_regex': {'regex': '(tierLiquidity|liquidity\\[|prizeLiquidity|availablePrize|remainingLiquidity)'}}, {'function.body_not_contains_regex': '(if\\s*\\(.*[Ll]iquidity\\s*==\\s*0\\s*\\)\\s*(return|continue|revert)|if\\s*\\(.*[Ll]iquidity\\s*>\\s*0\\s*\\)|require\\s*\\(.*[Ll]iquidity\\s*>\\s*0)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — prize-claim-zero-liquidity-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
