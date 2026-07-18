"""
glider-curve-virtual-price-read-only-reentrancy — generated from reference/patterns.dsl/glider-curve-virtual-price-read-only-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-curve-virtual-price-read-only-reentrancy.yaml
Source: glider-docs/bonus-challenge-1-curve-get_virtual_price-reentrancy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderCurveVirtualPriceReadOnlyReentrancy(AbstractDetector):
    ARGUMENT = "glider-curve-virtual-price-read-only-reentrancy"
    HELP = "External function reads Curve pool's `get_virtual_price()` without a Curve reentrancy-check sentinel or a local `nonReentrant` guard. A malicious pool state during `remove_liquidity` re-entry yields a skewed virtual price, allowing attackers to mint / borrow / redeem at wrong valuations."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-curve-virtual-price-read-only-reentrancy.yaml"
    WIKI_TITLE = "Curve `get_virtual_price()` consumed without reentrancy guard"
    WIKI_DESCRIPTION = "Curve's `get_virtual_price()` is only safe to read when the pool is not mid-operation. During `remove_liquidity` (and variants), Curve transfers native ETH / ERC-777 to the caller BEFORE settling internal state — giving the caller a re-entrancy window during which `get_virtual_price()` returns a manipulated value. Any consumer that uses this value for pricing collateral or minting LP-backed deriva"
    WIKI_EXPLOIT_SCENARIO = "A vault exposes `redeem()` that quotes shares at `pool.get_virtual_price() * totalSupply / 1e18`. Attacker calls `pool.remove_liquidity` with a native-ETH pool; mid-call the pool transfers ETH to the attacker, which re-enters `vault.redeem()`. `get_virtual_price()` observed inside the re-entry returns an inflated value — attacker redeems shares at ~2x their actual value. Seen live in multiple Curv"
    WIKI_RECOMMENDATION = "Before reading `get_virtual_price()`, assert pool is not locked by making a sentinel `pool.remove_liquidity(0, [0,0,...])` (reverts if locked) or call Curve's `claim_admin_fees()` sentinel. Additionally apply `nonReentrant` on the consuming external function. For LP-token valuations prefer a TWAP ov"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'get_virtual_price\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.get_virtual_price\\s*\\('}, {'function.body_not_contains_regex': 'remove_liquidity\\s*\\(\\s*0|claim_admin_fees|lock_oracle|is_killed|_checkReentrancy|reentrancy_lock'}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-curve-virtual-price-read-only-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
