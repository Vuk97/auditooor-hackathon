"""
tvl-excludes-queued-withdrawal-shares — generated from reference/patterns.dsl/tvl-excludes-queued-withdrawal-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py tvl-excludes-queued-withdrawal-shares.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-395
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TvlExcludesQueuedWithdrawalShares(AbstractDetector):
    ARGUMENT = "tvl-excludes-queued-withdrawal-shares"
    HELP = "TVL helper indexes queuedShares/queuedWithdrawals with the wrong key (address(this) vs token) so the queued leg is always zero."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/tvl-excludes-queued-withdrawal-shares.yaml"
    WIKI_TITLE = "TVL calculation mis-keys the queued-withdrawal map, silently deflating total assets"
    WIKI_DESCRIPTION = "When a yield vault computes TVL as (live strategy balance) + (queued-but-not-yet-completed withdrawal shares), a common copy-paste bug is to key the queuedShares mapping with `address(this)` when the variable is actually keyed by token address (or vice versa). The wrong key returns zero; the queued leg vanishes from TVL. Because the deposit path mints shares as `assets * totalSupply / TVL`, the un"
    WIKI_EXPLOIT_SCENARIO = "Renzo OperatorDelegator.getTokenBalanceFromStrategy reads `queuedShares[address(this)]` which is always 0 (the map is keyed by token). An admin-initiated queueWithdrawal removes 50e18 stETH from the live balance but the queued 50e18 is never added back, so TVL drops 50%. A depositor in the next block mints ezETH at 2× the legitimate rate."
    WIKI_RECOMMENDATION = "Audit every `mapping[...]` lookup used in TVL. Prefer a typed struct wrapper (`queuedShares.of(token)`) or enforce via unit tests that TVL == sum(live + queued) across a broad fuzz of states. Never silently fall back to zero on a missing key in TVL math."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'contract.name_matches: (?i)(operator.*delegator|restake.*manager|strategy.*vault|tvl.*calculator)']
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(getTokenBalance|getTVL|totalAssets|totalValue|calculateTVL|positionTVL|_getPositionTVL)'}, {'function.body_contains_regex': '(?i)(queuedShares|queuedWithdrawals|pendingWithdrawals|withdrawQueue)\\s*\\['}, {'function.body_contains_regex': '\\[\\s*(address\\(this\\)|msg\\.sender|self)\\s*\\]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — tvl-excludes-queued-withdrawal-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
