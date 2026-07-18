"""
profit-loss-else-if-drops-one-branch — generated from reference/patterns.dsl/profit-loss-else-if-drops-one-branch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py profit-loss-else-if-drops-one-branch.yaml
Source: auditooor-R75-c4-lending-loopfi-oct24-29
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ProfitLossElseIfDropsOneBranch(AbstractDetector):
    ARGUMENT = "profit-loss-else-if-drops-one-branch"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: `if (profit > 0) {...} else if (loss > 0) {...}` can skip the loss branch when lending profit and loss are both non-zero."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/profit-loss-else-if-drops-one-branch.yaml"
    WIKI_TITLE = "Profit / loss branches wired with `else if` drops coexistent loss"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Lending pool repayment paths may pass BOTH `profit` (interest earned this repayment) and `loss` (collateral shortfall when liquidating underwater debt) into a single settlement call. Intuitive but wrong structure: `if (profit > 0) mintShares(treasury); else if (loss > 0) burnShares(treasury);`. The loss branch never runs when both are positi"
    WIKI_EXPLOIT_SCENARIO = "Position: principal 1000, interest 500, total debt 1500. Collateral covers only 1440 (90% of 1600). Liquidator calls liquidate → `repayCreditAccount(1000, profit=500, loss=60)`. In the buggy implementation, 500 treasury shares are minted; the `else if` skips burning 60-worth of shares. LP shares now claim (assets - 60) with the same supply; exact symmetric drain for remaining LPs."
    WIKI_RECOMMENDATION = "Always use two separate `if` blocks: `if (profit > 0) { mintTreasury(profit); } if (loss > 0) { burnTreasury(loss); }`. Add an invariant post-condition that `abs(expectedLiquidity - (supply * sharePriceBefore)) < dust` and a fuzz test that exercises simultaneous profit and loss. Keep this row NOT_SU"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(repayCreditAccount|handleRepay|processRepay|profitOrLoss)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(repayCreditAccount|_?settleRepay|_?handleLoss|_?applyProfit|_?processProfitLoss)'}, {'function.body_contains_regex': '(?i)if\\s*\\(\\s*profit\\s*>\\s*0\\s*\\)\\s*\\{[^}]*(_mint|mint|mintProfit)[^}]*\\}\\s*else\\s+if\\s*\\(\\s*loss\\s*>\\s*0\\s*\\)\\s*\\{[^}]*(_burn|burn|burnLoss)[^}]*\\}'}, {'function.body_not_contains_regex': '(?i)(if\\s*\\(\\s*profit\\s*>\\s*0\\s*\\)\\s*\\{[^}]*\\}\\s*\\n\\s*if\\s*\\(\\s*loss\\s*>\\s*0|profit\\s*==\\s*0\\s*\\|\\|\\s*loss\\s*==\\s*0|assert.*profit.*==\\s*0.*loss)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — profit-loss-else-if-drops-one-branch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
