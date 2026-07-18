"""
swap-reenter-via-hook-midtx — generated from reference/patterns.dsl/swap-reenter-via-hook-midtx.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-reenter-via-hook-midtx.yaml
Source: solodit-cluster-C0252
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapReenterViaHookMidtx(AbstractDetector):
    ARGUMENT = "swap-reenter-via-hook-midtx"
    HELP = "Payable swap entrypoint invokes a beforeSwap/afterSwap/onSwap hook without nonReentrant — a user-controllable hook can reenter the same swap before state updates finalize, double-spending msg.value or extracting funds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-reenter-via-hook-midtx.yaml"
    WIKI_TITLE = "Swap reentrancy via hook mid-transaction callback"
    WIKI_DESCRIPTION = "A public payable swap function (Uniswap v4 `swap`, LI.FI `swapExact`, Bancor `exchange`, generic `trade`) invokes a beforeSwap / afterSwap / onSwap hook. If the hook callee is user-controllable (or a pool-key-selected contract in the v4 model) and no nonReentrant / lock modifier is applied, the hook can reenter the swap entrypoint before the outer balance accounting finalizes. The result is either"
    WIKI_EXPLOIT_SCENARIO = "1) Victim router exposes `swap(...) payable` which calls `hook.beforeSwap(poolKey, params)` before settling msg.value. 2) Attacker deploys a malicious hook and registers it in the poolKey (or supplies its address as the `hook` argument). 3) Attacker calls `swap` with msg.value = 1 ETH. 4) Inside `beforeSwap`, the attacker's hook reenters `swap` again with zero msg.value; the outer balance is still"
    WIKI_RECOMMENDATION = "Apply a reentrancy guard (`nonReentrant` / `lock`) on every external/public swap entrypoint that invokes a hook. Whitelist hook callees against an allowlist of protocol-owned addresses. Follow strict Check-Effects-Interactions: finalize msg.value accounting and transfer receivers before any beforeSw"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'beforeSwap|afterSwap|onSwap|IHook|SwapHook'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(swap|_swap|swapExact|exchange|trade)$'}, {'function.is_payable': True}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.body_contains_regex': 'beforeSwap|afterSwap|onSwap|hook\\.call|\\.beforeSwap\\s*\\(|\\.afterSwap\\s*\\('}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — swap-reenter-via-hook-midtx: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
