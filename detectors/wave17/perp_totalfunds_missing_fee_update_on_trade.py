"""
perp-totalfunds-missing-fee-update-on-trade — generated from reference/patterns.dsl/perp-totalfunds-missing-fee-update-on-trade.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-totalfunds-missing-fee-update-on-trade.yaml
Source: auditooor-R75-c4-2023-03-polynomial-H153-H152
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpTotalfundsMissingFeeUpdateOnTrade(AbstractDetector):
    ARGUMENT = "perp-totalfunds-missing-fee-update-on-trade"
    HELP = "Trade path collects fees from the trader but fails to add the net fee (collected - external) to `totalFunds`. The fee is sitting in the contract balance but the bookkeeping doesn't reflect it — `availableFunds = totalFunds - usedFunds` is understated; LP-token redemption price falls by the fee on ev"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-totalfunds-missing-fee-update-on-trade.yaml"
    WIKI_TITLE = "LP pool totalFunds not incremented by trading fees on openShort/closeLong etc."
    WIKI_DESCRIPTION = "Option/perp LP pools accept trader cash flow (premium + fees) and ledger the result with a `totalFunds` (or `totalAssets`) scalar. The share price paid to LPs on redemption is `totalFunds / totalSupply`. The trade function must update `totalFunds` by the NET fee `collectedFee - externalFee` (external fee goes to dev treasury). If only `usedFunds` is mutated and `totalFunds` is not, each trade leak"
    WIKI_EXPLOIT_SCENARIO = "(1) Pool has totalFunds=1_000_000, totalSupply=1_000_000 shares, share price = 1. (2) Trader opens a 100k short, pays 1_000 fees, of which 800 net fee (200 to dev). (3) `openShort` transfers 800 to the pool balance, but ONLY updates `usedFunds` (not `totalFunds`). (4) Another LP queries `availableFunds = totalFunds - usedFunds = 1_000_000 - 10_800` (if margin required is 10_000 plus 800 fees). Sha"
    WIKI_RECOMMENDATION = "After each trade, explicitly write `totalFunds += feesCollected - externalFee`. Additionally, make sure `usedFunds` does NOT include the `hedgingFees` because those were paid by the trader, not by the pool. Add a conservation-of-value invariant: after every trade, `token.balanceOf(pool) == totalFund"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(LiquidityPool|LPool|Exchange|PerpsVault|openShort|openLong|closeShort|closeLong)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(openShort|openLong|closeShort|closeLong|openTrade|closeTrade|executeTrade|_settleTrade)'}, {'function.body_contains_regex': '(feesCollected|tradeFee|orderFee|premiumFee|externalFee|devFee)'}, {'function.body_contains_regex': '(transfer|safeTransfer)\\s*\\([^)]*(user|trader|recipient)'}, {'function.body_not_contains_regex': '(totalFunds\\s*\\+=\\s*\\(?feesCollected|totalAssets\\s*\\+=|_accrueFee|pool\\s*\\+=|netFee)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-totalfunds-missing-fee-update-on-trade: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
