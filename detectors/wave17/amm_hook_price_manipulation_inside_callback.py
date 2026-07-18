"""
amm-hook-price-manipulation-inside-callback — generated from reference/patterns.dsl/amm-hook-price-manipulation-inside-callback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amm-hook-price-manipulation-inside-callback.yaml
Source: auditooor-round-34
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmmHookPriceManipulationInsideCallback(AbstractDetector):
    ARGUMENT = "amm-hook-price-manipulation-inside-callback"
    HELP = "Uniswap-v4-style hook reads live pool state (slot0/liquidity/fee) inside a swap/position callback and uses it to derive fees or adjustments. State at hook-entry is mid-action and attacker-manipulable via nested calls or JIT LP, so the derived value can be arbitrarily skewed."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amm-hook-price-manipulation-inside-callback.yaml"
    WIKI_TITLE = "v4 hook derives fees/adjustments from attacker-manipulable mid-swap pool state"
    WIKI_DESCRIPTION = "A Uniswap-v4-style hook implements beforeSwap / afterSwap / beforeModifyPosition / afterModifyPosition / beforeDonate / afterDonate and reads pool state — slot0, liquidity, fee, or positions — inside the callback to compute a dynamic fee, price bound, or custom-curve delta. Because the hook fires in the middle of a swap or position update, the pool state at the moment of the read is NOT a clean pr"
    WIKI_EXPLOIT_SCENARIO = "A dynamic-fee hook reads `poolManager.getSlot0(poolKey)` inside `beforeSwap` and charges a higher fee if the implied price has moved more than X% from the hook's last cached price. An attacker opens a JIT position that warps slot0 for the duration of their own swap, calls swap — the hook reads the warped slot0, thinks price has barely moved, and applies the minimum fee tier. After the swap the JIT"
    WIKI_RECOMMENDATION = "Do not read live pool state inside a hook callback to drive economic decisions. Instead take the snapshot at the start of the outer action — the PoolManager passes a pre-action state bundle into every hook; use those values. If a cached value is genuinely needed, write it to a hook-owned storage slo"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'beforeSwap|afterSwap|beforeModifyPosition|afterModifyPosition|beforeDonate|afterDonate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(beforeSwap|afterSwap|beforeModifyPosition|afterModifyPosition|beforeDonate|afterDonate)$'}, {'function.body_contains_regex': '\\.slot0\\s*\\(|\\.liquidity\\s*\\(|\\.fee\\s*\\(|pool\\.positions\\('}, {'function.body_not_contains_regex': 'snapshot|cachedSlot0|preHookState|_snapshotPool'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amm-hook-price-manipulation-inside-callback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
