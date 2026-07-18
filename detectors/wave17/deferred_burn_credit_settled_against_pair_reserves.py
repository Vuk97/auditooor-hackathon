"""
deferred-burn-credit-settled-against-pair-reserves — generated from reference/patterns.dsl/deferred-burn-credit-settled-against-pair-reserves.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deferred-burn-credit-settled-against-pair-reserves.yaml
Source: defimon-2026-04/mona-bsc-60K
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DeferredBurnCreditSettledAgainstPairReserves(AbstractDetector):
    ARGUMENT = "deferred-burn-credit-settled-against-pair-reserves"
    HELP = "Token sell-leg records deferred burn credit on a separate registry instead of burning inline; a later non-pair transfer fires burn() which transfers MONA out of the AMM pair via transferFrom + sync(), letting the attacker cancel the token side of a prior swap on chosen timing."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deferred-burn-credit-settled-against-pair-reserves.yaml"
    WIKI_TITLE = "Deferred-burn credit settled against AMM pair reserves on later non-pair-transfer trigger"
    WIKI_DESCRIPTION = "Three-contract structural shape. (1) ERC20 token's `_update` hook routes pair-destination transfers to `_handleSell()` which transfers MONA into the AMM pair, the seller receives USDT, AND registers `burnAddress.sellMona += monaTransfer` as DEFERRED future-burn credit instead of burning inline. (2) The same `_update` hook routes any later non-pair-destination transfer to `burnAddress.burn()` — inc"
    WIKI_EXPLOIT_SCENARIO = "MONA on BSC, Apr 14 2026, $60,950 USDT (tx 0x3a60e1...7ea4). Attacker (a) sold a small amount of MONA legitimately to register a sellMona credit. (b) Front-ran a victim swap or just observed the pair state. (c) Called `transferFrom(0xdeed, 0xdeed, 0)` on MONA — zero-value transfer, enters the non-pair branch of `_update`, triggers `burnAddress.burn()`, which transferFrom-pulls MONA from `lpPairAdd"
    WIKI_RECOMMENDATION = "Settle the burn INLINE inside `_handleSell` BEFORE the pair receives the swap output: either `_burn(seller, monaTransfer)` directly, or `balances[lpPair] -= monaTransfer; balances[deadAddress] += monaTransfer; IUniswapV2Pair(lpPair).sync();` synchronously, or refuse to maintain a deferred-burn regis"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(burnAddress|burnRegistry|burnTracker|burnVault|sellMona|pendingBurn|deferredBurn|sellRecord|sellAmount)'}, {'contract.has_state_var_matching': '(?i)(lpPair|uniswapPair|pancakePair|_pair|pairAddress|burnAddress|burnRegistry|burnTracker)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^(_update|_transfer|_beforeTokenTransfer|_afterTokenTransfer|_handleSell|handleSell|_recordSell|_processSell|_doSell)\\w*$'}, {'function.body_contains_regex': '(?i)(^|[\\s({;,])(sellMona|sellAmount|pendingBurn|deferredBurn|sellRecord|burnQueue|toBurn)\\s*[+]?=|burnAddress\\s*\\.\\s*(\\w+\\s*[+]?=|recordSell|recordSettled|burn|settle|process|trigger|flush)\\s*[(=]|burnRegistry\\s*\\.\\s*(\\w+\\s*[+]?=|recordSell|burn|settle|process|trigger|flush)\\s*[(=]|burnTracker\\s*\\.\\s*(\\w+\\s*[+]?=|recordSell|burn|settle|process|trigger|flush)\\s*[(=]'}, {'function.body_contains_regex': '(?i)to\\s*==\\s*(lpPair|pair|uniswapPair|pancakePair|_pair)|to\\s*!=\\s*(lpPair|pair|uniswapPair|pancakePair|_pair)|burnAddress\\s*\\.\\s*(burn|settle|process|trigger|flush)\\s*\\(|burnRegistry\\s*\\.\\s*(burn|settle|process|trigger|flush)\\s*\\(|burnTracker\\s*\\.\\s*(burn|settle|process|trigger|flush)\\s*\\('}, {'function.body_not_contains_regex': '(?i)_burn\\s*\\(\\s*(lpPair|pair|address\\(this\\)|seller)|balances?\\s*\\[\\s*(deadAddress|0x000000000000000000000000000000000000dEaD)\\s*\\]\\s*[+]?=|balanceOf\\s*\\[\\s*lpPair\\w*\\s*\\]\\s*-=|IUniswapV2Pair\\s*\\(\\s*lpPair\\w*\\s*\\)\\.sync\\s*\\(\\s*\\)|emit\\s+SellSettled'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deferred-burn-credit-settled-against-pair-reserves: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
