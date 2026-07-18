"""
decimal-multiplier-above-18-underflow — generated from reference/patterns.dsl/decimal-multiplier-above-18-underflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py decimal-multiplier-above-18-underflow.yaml
Source: solodit/decimals-above-18
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DecimalMultiplierAbove18Underflow(AbstractDetector):
    ARGUMENT = "decimal-multiplier-above-18-underflow"
    HELP = "Contract scales token amounts as `amount * 10 ** (18 - decimals)` without branching on `decimals > 18`. For high-decimals tokens (e.g. Nexo's legacy 24-decimal variants) this reverts on the exponent or underflows into an astronomical multiplier — deposits and withdrawals break or silently mis-price."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/decimal-multiplier-above-18-underflow.yaml"
    WIKI_TITLE = "Decimal scaling assumes `decimals <= 18`: tokens with >18 decimals mis-price or DoS"
    WIKI_DESCRIPTION = "Protocols that accept heterogeneous ERC-20 collateral frequently normalise to 18 decimals via `amount * 10 ** (18 - decimals)`. When the underlying token reports `decimals() > 18` (perfectly legal by EIP-20, and real on some legacy assets), the subexpression `18 - decimals` either reverts (Solidity 0.8 checked math) — DoS-ing any deposit/withdraw — or, in unchecked blocks, wraps to a massive uint,"
    WIKI_EXPLOIT_SCENARIO = "A listing committee onboards a legacy yield-bearing token with `decimals = 24`. The vault's `_handleDeposit` executes `amount * 10 ** (18 - decimals)`. Solidity 0.8 reverts on `18 - 24`, making every deposit and withdrawal of that token impossible — funds already deposited via a separate path cannot be withdrawn. In an unchecked-math version, the exponent wraps to 2^256-6 and the multiplier overfl"
    WIKI_RECOMMENDATION = "Branch on `decimals <= 18` vs `decimals > 18`: multiply in the first case, divide in the second. Alternatively enforce `require(decimals <= 18)` at token-onboarding time — but document the restriction and reject unsupported tokens at the gate rather than at the user's transaction."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'decimals\\s*\\(|IERC20Metadata|\\.decimals\\(\\)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(deposit|depositFor|withdraw|withdrawTo|convert|convertToAssets|convertToShares|normalize|normalizeAmount|scale|scaleAmount|handleDeposit|handleWithdraw|toBase|fromBase|_deposit|_withdraw|_scale|_normalize)$'}, {'function.body_contains_regex': '10\\s*\\*\\*\\s*\\(\\s*18\\s*-\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*\\)|10\\s*\\*\\*\\s*\\(\\s*decimals?\\s*-\\s*18'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*decimals\\s*<=\\s*18|if\\s*\\(\\s*decimals\\s*>\\s*18|decimals\\s*>=\\s*18'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — decimal-multiplier-above-18-underflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
