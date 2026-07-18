"""
prediction-market-oracle-void-outcome-minus-one-payouts-never-set — generated from reference/patterns.dsl/prediction-market-oracle-void-outcome-minus-one-payouts-never-set.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py prediction-market-oracle-void-outcome-minus-one-payouts-never-set.yaml
Source: auditooor-R76-cyfrin-myriad-clob-H1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PredictionMarketOracleVoidOutcomeMinusOnePayoutsNeverSet(AbstractDetector):
    ARGUMENT = "prediction-market-oracle-void-outcome-minus-one-payouts-never-set"
    HELP = "resolveMarket accepts oracle outcome -1 (void) and marks market Resolved but never populates voidedPayouts. redeemVoided asserts payout sum == 1e18 and reverts forever → collateral stuck."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/prediction-market-oracle-void-outcome-minus-one-payouts-never-set.yaml"
    WIKI_TITLE = "Prediction market: oracle void outcome -1 leaves voidedPayouts unset → permanent collateral lock"
    WIKI_DESCRIPTION = "A CTF/prediction-market manager resolves markets by reading the oracle: if the outcome is the void sentinel (`-1`, `0xffff...fff` in reality.eth's int256 encoding) the code still updates `market.resolvedOutcome` and transitions `MarketState.Resolved`, but does NOT populate the companion `voidedPayouts[marketId]` mapping (which `ConditionalTokens::redeemVoided` reads and asserts must sum to 1e18). "
    WIKI_EXPLOIT_SCENARIO = "Reality.eth question times out or the arbitrator returns 'invalid': getResult returns (-1, true). Admin calls `resolveMarket(mid)`; outcome=-1 is accepted, `resolvedOutcome=-1`, `voidedPayouts[mid]` remains [0,0]. Any holder of outcome-0 or outcome-1 tokens calls `redeemVoided` → `require(0+0==1e18)` reverts. Collateral (USDC) is locked. Only a proxy upgrade with a new void path can rescue it."
    WIKI_RECOMMENDATION = "In `resolveMarket`, reject `outcome == -1` (`require(outcome == 0 || outcome == 1)`) and route all voiding through a dedicated `adminVoidMarket(mid, p0, p1)` that validates `p0+p1 == 1e18` and writes to `voidedPayouts[mid]`. Add an invariant: for every resolved market, either `resolvedOutcome ∈ {0,1"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)ConditionalTokens|PredictionMarket|CTFExchange|MarketManager|Realitio'}, {'contract.has_function_matching': '(?i)resolveMarket|finalizeOutcome|settleMarket|onOutcomeReported'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)resolveMarket|settleOutcome|finalizeMarket|reportOutcome'}, {'function.body_contains_regex': '(?i)outcome\\s*==\\s*-1|outcome\\s*==\\s*(int256|int128)\\s*\\(\\s*-1\\s*\\)|INVALID_OUTCOME|isVoided'}, {'function.body_contains_regex': '(?i)MarketState\\.(resolved|Resolved)|state\\s*=\\s*MarketState'}, {'function.body_not_contains_regex': '(?i)voidedPayouts\\s*\\[.*\\]\\s*=|payoutRatios\\[|setPayouts\\(|adminVoidMarket'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — prediction-market-oracle-void-outcome-minus-one-payouts-never-set: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
