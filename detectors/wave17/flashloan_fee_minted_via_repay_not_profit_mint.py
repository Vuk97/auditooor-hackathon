"""
flashloan-fee-minted-via-repay-not-profit-mint — generated from reference/patterns.dsl/flashloan-fee-minted-via-repay-not-profit-mint.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py flashloan-fee-minted-via-repay-not-profit-mint.yaml
Source: auditooor-R73-code4rena-2024-07-loopfi-55
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FlashloanFeeMintedViaRepayNotProfitMint(AbstractDetector):
    ARGUMENT = "flashloan-fee-minted-via-repay-not-profit-mint"
    HELP = "Flash-loan fee accounted via borrower-debt-repay hook instead of dedicated mintProfit; expectedLiquidity stays stale and later withdrawals underflow."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/flashloan-fee-minted-via-repay-not-profit-mint.yaml"
    WIKI_TITLE = "Flash-loan fee routed through repay hook leaves expectedLiquidity stale"
    WIKI_DESCRIPTION = "Lending pools that track `expectedLiquidity` independently from on-chain balance expose two settlement hooks: `repayCreditAccount(repaid, profit, loss)` (profit is already counted in expectedLiquidity via accrued interest) and `mintProfit(amount)` (adds a fresh profit delta). A flash-loan contract that routes fees through `repayCreditAccount` accidentally understates expectedLiquidity by the fee a"
    WIKI_EXPLOIT_SCENARIO = "Pool has balance 100 WETH, expectedLiquidity=100. A user takes a 1000 WETH flashloan with 10 WETH fee. Flashlender calls repayCreditAccount(1000, 10, 0); expectedLiquidity stays 100 but balance is now 110. When all LPs try to withdraw, the `_updateBaseInterest` on the last exit reverts with arithmetic underflow because expectedLiquidity drops below real balance."
    WIKI_RECOMMENDATION = "Call `mintProfit(fee)` for flash-loan fees (fresh profit that must raise expectedLiquidity), and reserve `repayCreditAccount` for borrower debt settlement (where profit was already accrued in expectedLiquidity). Add a post-condition test: after every state-changing hook, assert `underlying.balanceOf"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)flashLoan|onFlashLoan'}, {'function.body_contains_regex': '(?i)(repayCreditAccount|repayDebt)\\s*\\(\\s*\\w+\\s*-\\s*fee\\s*,\\s*fee'}, {'function.body_not_contains_regex': '(?i)mintProfit|updateLiquidity.*\\+\\s*fee'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — flashloan-fee-minted-via-repay-not-profit-mint: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
