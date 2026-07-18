"""
glider-uniswap-v4-hook-missing-pool-manager-check — generated from reference/patterns.dsl/glider-uniswap-v4-hook-missing-pool-manager-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-uniswap-v4-hook-missing-pool-manager-check.yaml
Source: hexens-glider/uniswap-v4-hook-functions-fail-to-verify-msgsender
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUniswapV4HookMissingPoolManagerCheck(AbstractDetector):
    ARGUMENT = "glider-uniswap-v4-hook-missing-pool-manager-check"
    HELP = "Uniswap-v4 hook function (`beforeSwap`, `afterSwap`, …) is callable without asserting `msg.sender == poolManager`. The Cork Protocol $11M exploit (Dedaub) abused exactly this — attackers called hooks directly with crafted PoolKeys to manipulate internal state the hook assumed was only ever written f"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-uniswap-v4-hook-missing-pool-manager-check.yaml"
    WIKI_TITLE = "Uniswap-v4 hook fails to verify msg.sender is PoolManager"
    WIKI_DESCRIPTION = "Every hook entry in a v4 Hook contract must carry the `onlyPoolManager` modifier (or an equivalent inline check), matching the pattern in `v4-periphery/BaseHook`. When the hook is callable by arbitrary addresses, the hook's internal state (position deltas, swap routing decisions, accounting counters) can be driven to adversarial values without an actual pool interaction happening — the Cork Protoc"
    WIKI_EXPLOIT_SCENARIO = "Hook contract exposes `beforeSwap(address sender, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata hookData)` without an `onlyPoolManager` modifier. Attacker calls it directly with a fabricated `PoolKey` matching the victim pool's ID. The hook updates its internal `lastSwapAmount` / price cache / fee-accrual state under the assumption that this was a real PoolManager c"
    WIKI_RECOMMENDATION = "Inherit from `BaseHook` which supplies the `onlyPoolManager` modifier, OR add it manually: `modifier onlyPoolManager() { require(msg.sender == address(poolManager), \"not PM\"); _; }`. Apply to ALL ten hook entry points, not just `beforeSwap`. Audit that `unlockCallback` is similarly gated."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'PoolKey|IPoolManager|poolManager|PoolManager'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(beforeSwap|afterSwap|beforeDonate|afterDonate|beforeAddLiquidity|afterAddLiquidity|beforeRemoveLiquidity|afterRemoveLiquidity|beforeInitialize|afterInitialize|unlockCallback)$'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(?:poolManager|_poolManager|POOL_MANAGER|manager)|onlyPoolManager'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — glider-uniswap-v4-hook-missing-pool-manager-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
