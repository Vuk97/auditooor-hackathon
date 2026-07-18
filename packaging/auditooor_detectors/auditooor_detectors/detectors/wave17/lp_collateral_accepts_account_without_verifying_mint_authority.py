"""
lp-collateral-accepts-account-without-verifying-mint-authority — generated from reference/patterns.dsl/lp-collateral-accepts-account-without-verifying-mint-authority.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lp-collateral-accepts-account-without-verifying-mint-authority.yaml
Source: auditooor-R76-rekt-cashio-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LpCollateralAcceptsAccountWithoutVerifyingMintAuthority(AbstractDetector):
    ARGUMENT = "lp-collateral-accepts-account-without-verifying-mint-authority"
    HELP = "Collateral-accepting function verifies the deposited token's legitimacy by calling a getter on the TOKEN (self-attestation) rather than looking it up in a protocol-owned registry. Attacker deploys a fake pair that returns the canonical factory's address."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lp-collateral-accepts-account-without-verifying-mint-authority.yaml"
    WIKI_TITLE = "LP / pair collateral validated by self-reported factory, not by registry lookup"
    WIKI_DESCRIPTION = "Lending and stablecoin-issuance protocols often accept Uniswap-V2-style LP tokens (or Saber/Raydium PDAs on Solana) as collateral. A common validation footgun is to accept any `lpToken` argument and verify its legitimacy by calling `lpToken.factory()` or `lpToken.token0()` and comparing to expected values. A hostile contract can return ANYTHING from these getters, so self-attestation proves nothin"
    WIKI_EXPLOIT_SCENARIO = "Cashio (Solana) / EVM analogue: Attacker deploys FakePair. `FakePair.factory()` returns canonical UniswapV2Factory address. `FakePair.token0()` returns USDC. `FakePair.token1()` returns USDT. `FakePair.balanceOf(attacker)` returns 1e24. Attacker calls `CashLender.depositCollateral(FakePair, 1e24)`. Contract verifies factory matches, token0/token1 are whitelisted stablecoins, and balance is correct"
    WIKI_RECOMMENDATION = "Validate collateral via registry lookup, not self-attestation. Use `require(canonicalFactory.getPair(token0, token1) == lpToken, 'not a real pair');` — this verifies the factory itself acknowledges the pair. Alternatively, maintain an admin-curated `allowedCollateral[address] = bool` mapping and req"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Function accepts a token/account as collateral and verifies its legitimacy by calling a getter on the token itself (self-attestation) rather than by registry lookup.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)depositCollateral|addCollateral|mintWithCollateral|depositLP|mint\\w*With|openPosition'}, {'function.body_contains_regex': '(?i)IPair\\([^)]+\\)\\.factory\\s*\\(\\s*\\)|\\.token0\\s*\\(\\s*\\)|\\.token1\\s*\\(\\s*\\)|\\.mintAuthority|pair\\.factory|factoryOf'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^;]*registry\\.isApprovedPair|isWhitelistedLP|allowedCollateralToken\\s*\\[|officialFactory\\s*==\\s*IPair\\([^)]+\\)\\.factory\\s*\\(\\s*\\)\\s*;\\s*require\\s*\\(.*codehash'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lp-collateral-accepts-account-without-verifying-mint-authority: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
