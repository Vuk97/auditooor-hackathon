"""
r74-precision-rounding-free-liquidity-mint — generated from reference/patterns.dsl/r74-precision-rounding-free-liquidity-mint.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-precision-rounding-free-liquidity-mint.yaml
Source: r74b-cross-firm-tob+cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74PrecisionRoundingFreeLiquidityMint(AbstractDetector):
    ARGUMENT = "r74-precision-rounding-free-liquidity-mint"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: mint/deposit computes required assets from requested shares with floor division, so dust shares can mint against zero required input."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-precision-rounding-free-liquidity-mint.yaml"
    WIKI_TITLE = "Rounding-down on share-to-amount conversion mints free liquidity"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. AMM and vault mint functions that let the user specify the share amount must compute the required input using ceiling division to preserve the invariant `shares * pricePerShare <= input`. When floor division is used, and no minimum-amount check rejects zero-input mints, an attacker can request 1 share and pay 0 input (gas cost only). The che"
    WIKI_EXPLOIT_SCENARIO = "A concentrated-liquidity pool's mint function accepts desired-shares and computes required-token0 = shares * reserve0 / totalSupply (floor division). When shares = 1 and totalSupply is large enough that shares * reserve0 < totalSupply, required-token0 = 0. The attacker mints 1 share per transaction for ~$0.50 gas, pockets claim rights on existing LP-accrued fees proportional to their share. Done 1"
    WIKI_RECOMMENDATION = "For every share-to-amount computation on the mint/deposit path, use ceiling division (mulDivUp / Math.mulDiv with Rounding.Up). Additionally, require the computed amount is strictly positive before mint (`require(amount > 0, 'zero input')`). Invariant-test: for any share amount, the deposit-then-wit"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(mint|deposit|addLiquidity)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(mint|deposit|addLiquidity|_mint)$'}, {'function.writes_storage_matching': 'totalSupply|balances|shares'}, {'function.body_contains_regex': 'amount\\s*=\\s*.*shares\\s*\\*|required\\s*=\\s*.*shares\\s*[\\*/]|mulDiv\\s*\\(\\s*shares'}, {'function.body_not_contains_regex': 'mulDivUp|mulDivRoundingUp|ceilDiv|\\+\\s*1\\s*\\)\\s*\\/|Math\\.Rounding\\.Up|Math\\.ceilDiv'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*amount\\s*>\\s*0|require\\s*\\(\\s*required\\s*>\\s*0|require\\s*\\(\\s*\\w+\\s*>=\\s*MIN_|require\\s*\\(\\s*deposit\\s*>=\\s*1'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-precision-rounding-free-liquidity-mint: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
