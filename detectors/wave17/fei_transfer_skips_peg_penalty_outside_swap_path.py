"""
fei-transfer-skips-peg-penalty-outside-swap-path — generated from reference/patterns.dsl/fei-transfer-skips-peg-penalty-outside-swap-path.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fei-transfer-skips-peg-penalty-outside-swap-path.yaml
Source: auditooor-R76-immunefi-fei-transfer-penalty
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeiTransferSkipsPegPenaltyOutsideSwapPath(AbstractDetector):
    ARGUMENT = "fei-transfer-skips-peg-penalty-outside-swap-path"
    HELP = "Buy-reward / sell-penalty logic keys off Uniswap reserves that only update on swap(). Direct ERC-20 transfer to the pair address moves tokens without triggering penalties — attacker farms rewards then exits penalty-free."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fei-transfer-skips-peg-penalty-outside-swap-path.yaml"
    WIKI_TITLE = "Peg-enforcement penalty skipped on direct transfer into Uniswap pair"
    WIKI_DESCRIPTION = "A stablecoin that applies buy rewards (price above peg) and sell penalties (price below peg) computes the peg status from a Uniswap pair's cached reserves. Reserves only refresh when `swap()` is invoked — a plain `transfer(pair, amount)` moves tokens in/out without updating reserves. Attacker: (1) swap WETH→FEI to push price above peg, collecting mint reward, (2) transfer FEI directly into the pai"
    WIKI_EXPLOIT_SCENARIO = "Fei's rebasing/penalty logic read Uniswap reserves. Attacker swapped WETH→FEI at pair (price goes above peg, mint reward emitted), then Fei.transfer'd the FEI straight into the pair (reserves unchanged, no penalty), then swapped back. Net profit from reward minus zero penalty. Fei Labs disabled rewards/penalties entirely as fix."
    WIKI_RECOMMENDATION = "Penalty/reward accounting must NOT depend on pool-reserve side-effects. Use an external oracle (Chainlink, TWAP) evaluated at the start of the transfer to determine peg status. Apply the same penalty to every `_transfer`, not just swap-derived transfers. Alternative: disable transfer to/from whiteli"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_buy_reward_or_sell_penalty': True}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)^_transfer$|^transfer$|^_update$'}, {'function.body_contains_regex': '(?i)reserves|IUniswapV2Pair|getReserves'}, {'function.body_not_contains_regex': '(?i)isPenaltyApplied|applyPenalty\\s*\\(|_distributeFee|oracle\\.price|twapPrice'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fei-transfer-skips-peg-penalty-outside-swap-path: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
