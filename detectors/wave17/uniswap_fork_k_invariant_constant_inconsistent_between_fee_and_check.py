"""
uniswap-fork-k-invariant-constant-inconsistent-between-fee-and-check — generated from reference/patterns.dsl/uniswap-fork-k-invariant-constant-inconsistent-between-fee-and-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-fork-k-invariant-constant-inconsistent-between-fee-and-check.yaml
Source: auditooor-R76-rekt-uranium-finance-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapForkKInvariantConstantInconsistentBetweenFeeAndCheck(AbstractDetector):
    ARGUMENT = "uniswap-fork-k-invariant-constant-inconsistent-between-fee-and-check"
    HELP = "Uniswap-V2 fork swap() uses magic numbers 1000 and/or 10000 in fee-adjusted k check. If the fee denominator was changed without updating every occurrence (including the squared constant), the invariant no longer constrains the swap."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-fork-k-invariant-constant-inconsistent-between-fee-and-check.yaml"
    WIKI_TITLE = "Uniswap-V2-style swap uses inconsistent fee-denominator magic numbers across fee math and k-check"
    WIKI_DESCRIPTION = "Uniswap V2's `swap()` multiplies input balances by `(1000 - fee)` and checks `balance0Adjusted * balance1Adjusted >= reserve0 * reserve1 * (1000**2)`. Forks that adjust the fee (e.g. 9975/10000 instead of 997/1000) must update BOTH the numerator AND the squared constant in the invariant. Leaving the squared constant at 1_000_000 while scaling the numerator to 10_000 makes the LHS grow 100x vs the "
    WIKI_EXPLOIT_SCENARIO = "Uranium's UraniumPair has `balance0Adjusted = balance0.mul(10000).sub(amount0In.mul(25))` (0.25% fee, denominator 10000). But the check is `balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(1000**2)`. Attacker sends 1 wei of token0 to the pair and calls `swap(0, almostAllToken1, attacker, '')`. LHS = ~(_reserve0 * 10000) * (small balance1) which dwarfs RHS = _reserve0 * "
    WIKI_RECOMMENDATION = "Define ONE constant `uint256 constant FEE_DENOMINATOR = 10000;` and use it everywhere. The invariant must be `balance0Adjusted * balance1Adjusted >= _reserve0 * _reserve1 * FEE_DENOMINATOR**2`. Add a unit test: simulate a 1-wei swap and assert revert. Ideally use OpenZeppelin's `Math.mulDiv` and par"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Uniswap-V2 fork swap() uses a fee adjustment constant (e.g. 997/1000 or 9975/10000) that must appear identically in both the per-input fee deduction and the post-swap k-invariant check (squared).']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^swap$|^_swap$|low[Ll]evelSwap'}, {'function.body_contains_regex': '(?i)balance0Adjusted|balance1Adjusted|balance\\w*\\s*\\.\\s*mul\\s*\\(\\s*(1000|10000)|\\*\\s*(1000\\s*\\*\\*\\s*2|1_000_000|100000000|10000\\s*\\*\\*\\s*2)'}, {'function.body_not_contains_regex': '(?i)// FEE_DENOMINATOR verified|FEE_DENOM\\s*\\*\\*\\s*2|_FEE_DENOM\\s*=|require\\s*\\(\\s*FEE_DENOM\\s*==\\s*FEE_DENOM'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-fork-k-invariant-constant-inconsistent-between-fee-and-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
