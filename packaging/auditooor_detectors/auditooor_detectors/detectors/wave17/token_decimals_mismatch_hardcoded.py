"""
token-decimals-mismatch-hardcoded — generated from reference/patterns.dsl/token-decimals-mismatch-hardcoded.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py token-decimals-mismatch-hardcoded.yaml
Source: solodit/C0189
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TokenDecimalsMismatchHardcoded(AbstractDetector):
    ARGUMENT = "token-decimals-mismatch-hardcoded"
    HELP = "Deposit/withdraw/pricing function hardcodes `* 1e18` or `/ 1e18` (or `10 ** 18`, `DECIMALS`) on an ERC20 amount without reading the token's decimals() — breaks for USDC (6), WBTC (8), and tokens with >18 decimals."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/token-decimals-mismatch-hardcoded.yaml"
    WIKI_TITLE = "Token decimals mismatch: hardcoded 1e18 scaling without reading token decimals()"
    WIKI_DESCRIPTION = "The function multiplies or divides an ERC20 amount by a literal 1e18 (or 10**18, or a DECIMALS constant) and does not call token.decimals() or route through a decimal-normalisation adapter. ERC20 tokens publish different decimal counts: USDC and USDT (6), WBTC (8), MKR/DAI-family (18), GUSD (2), and a handful of long-tail tokens (>18). A _handleDeposit or _handleWithdraw that bakes in 18 silently "
    WIKI_EXPLOIT_SCENARIO = "Pool admin lists USDC (6 decimals) on a handler that performs `amount * 1e18` when crediting shares. A user deposits 1 USDC (1_000_000 units on the wire) and the handler credits them with 1_000_000 * 1e18 worth of shares — a 1e12 over-credit — letting them withdraw virtually the entire pool. Symmetrically, a high-decimal token (>18) listed against `/ 1e18` silently rounds user balances to zero, lo"
    WIKI_RECOMMENDATION = "Read `IERC20Metadata(token).decimals()` at configuration (cache per-token) and scale via `10 ** decimals` dynamically, or wrap every token in an adapter that exposes a fixed-precision interface. Reject tokens whose decimals() falls outside an allowed band (e.g., [2, 24])."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': '\\*\\s*1e18\\b|\\/\\s*1e18\\b|\\*\\s*10\\s*\\*\\*\\s*18\\b|\\*\\s*DECIMALS|1e18\\s*\\*\\s*amount|amount\\s*\\*\\s*1e18'}}, {'function.body_not_contains_regex': '\\.decimals\\s*\\(|tokenDecimals|scaleBy|scalar|normalizeDecimals'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — token-decimals-mismatch-hardcoded: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
