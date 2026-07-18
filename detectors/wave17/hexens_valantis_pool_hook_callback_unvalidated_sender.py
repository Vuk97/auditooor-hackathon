"""
hexens-valantis-pool-hook-callback-unvalidated-sender — generated from reference/patterns.dsl/hexens-valantis-pool-hook-callback-unvalidated-sender.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hexens-valantis-pool-hook-callback-unvalidated-sender.yaml
Source: auditooor-R75-hexens-Valantis-UniswapV4Style-HookCallback
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HexensValantisPoolHookCallbackUnvalidatedSender(AbstractDetector):
    ARGUMENT = "hexens-valantis-pool-hook-callback-unvalidated-sender"
    HELP = "Pool hook (Uniswap V4 / Valantis style) does not restrict who can invoke `beforeSwap`/`afterSwap`/`unlockCallback` — any EOA can call directly, bypassing the pool's economic invariants and potentially draining hook-held reserves."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hexens-valantis-pool-hook-callback-unvalidated-sender.yaml"
    WIKI_TITLE = "Pool hook callback lacks onlyPoolManager guard — arbitrary invocation"
    WIKI_DESCRIPTION = "Uniswap V4 and V4-style AMMs (Valantis SOT / ALM, Bunni V2, Uniswap X hooks) delegate pre/post-action logic to hook contracts. Hooks are intended to be invoked only via the pool-manager's locked-call context, with `msg.sender == manager`. Forgetting this check on a public hook entrypoint lets any address call `beforeSwap`, `afterSwap`, `unlockCallback`, etc. with attacker-chosen parameters — updat"
    WIKI_EXPLOIT_SCENARIO = "Valantis ALM hook: `afterSwap(params, result)` updates the hook's `lastPrice` and `cumulativeVolume` for its TWAP. No `require(msg.sender == manager)`. Attacker calls `afterSwap` directly with params showing price=1e18 (oracle manipulation); hook's `lastPrice` is now attacker-controlled. Downstream consumers (a lending market using the hook's TWAP) see the stale/fake price and issue mis-priced liq"
    WIKI_RECOMMENDATION = "Every external hook entrypoint MUST start with `require(msg.sender == address(poolManager), 'not-manager');` (or an equivalent modifier `onlyPoolManager`). Store `poolManager` as `immutable`. Review each of the ~8 V4 hook flags (`before/afterInitialize`, `before/afterSwap`, `before/afterAddLiquidity"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Valantis|PoolManager|Hook|beforeSwap|afterSwap|beforeAddLiquidity|uniswapV4'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'beforeSwap|afterSwap|beforeAddLiquidity|afterRemoveLiquidity|unlockCallback|lockAcquired|_callHook'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': 'msg\\.sender|_msgSender'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(POOL_MANAGER|poolManager|manager|pool|VAULT)|onlyPoolManager|_onlyPoolManager|require\\s*\\(\\s*msg\\.sender\\s*==\\s*address\\(manager\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hexens-valantis-pool-hook-callback-unvalidated-sender: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
