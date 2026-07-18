"""
curve-pool-lp-token-call-without-fallback-to-token — generated from reference/patterns.dsl/curve-pool-lp-token-call-without-fallback-to-token.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py curve-pool-lp-token-call-without-fallback-to-token.yaml
Source: lisa-mine-r99-case-02271-sherlock-notional-2023-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CurvePoolLpTokenCallWithoutFallbackToToken(AbstractDetector):
    ARGUMENT = "curve-pool-lp-token-call-without-fallback-to-token"
    HELP = "Curve pool integration calls `pool.lp_token()` and assumes it returns the LP token address. New-style Curve pools (post-2022 CryptoPool / TwoCryptoPool variants such as CRV/ETH) do not implement `lp_token()`; the call hits the fallback function and returns zero. The integrating vault then stores `ad"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/curve-pool-lp-token-call-without-fallback-to-token.yaml"
    WIKI_TITLE = "Curve pool integration calls `lp_token()` without falling back to `token()`"
    WIKI_DESCRIPTION = "Pattern fires on Curve-pool wrappers that call `CURVE_POOL.lp_token()` directly with no `try / catch`, no fallback to `pool.token()`, and no zero-address check on the returned address. Old-style Curve pools expose `lp_token()`; new-style CryptoPool / TwoCryptoPool variants instead expose `token()`. Calling `lp_token()` on the new variant hits the Vyper fallback and returns the zero address — the w"
    WIKI_EXPLOIT_SCENARIO = "Notional governance whitelists CRV/ETH (new-style TwoCryptoPool) for a leveraged vault. The vault constructor runs `CURVE_POOL_TOKEN = IERC20(CURVE_POOL.lp_token())` — Vyper fallback returns 0. Vault deploys successfully (constructor does not revert because `IERC20(address(0))` is valid Solidity). Every subsequent `claimReward / settle / convertPoolClaimToStrategyTokens` call reverts when it touch"
    WIKI_RECOMMENDATION = "Use a try/catch with a fallback: `try ICurvePool(pool).lp_token() returns (address t) { lpTok = t; } catch { lpTok = ICurvePool(pool).token(); }`. Always require `lpTok != address(0)` after the resolution. Alternatively, take the LP token address as a constructor parameter and re-derive it off-chain"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ICurvePool|CurvePool|curve\\.fi|CurveTwoCryptoPool|CryptoPool'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '\\.lp_token\\s*\\(\\s*\\)'}, {'function.body_not_contains_regex': '\\.token\\s*\\(\\s*\\)|try\\s+[A-Za-z_][A-Za-z0-9_]*\\.lp_token|address\\s*\\(\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — curve-pool-lp-token-call-without-fallback-to-token: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
