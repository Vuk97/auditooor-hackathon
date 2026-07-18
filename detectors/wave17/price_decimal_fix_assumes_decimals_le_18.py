"""
price-decimal-fix-assumes-decimals-le-18 — generated from reference/patterns.dsl/price-decimal-fix-assumes-decimals-le-18.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py price-decimal-fix-assumes-decimals-le-18.yaml
Source: lisa-mine-r99-case-01648-sherlock-dodo-2023-06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PriceDecimalFixAssumesDecimalsLe18(AbstractDetector):
    ARGUMENT = "price-decimal-fix-assumes-decimals-le-18"
    HELP = "Price-fixing helper computes `fixDecimal = 18 - tokenDecimal` and scales bid/ask prices by `10 ** fixDecimal` without first branching on `tokenDecimal > 18`. Tokens with `decimals() > 18` (perfectly EIP-20 legal — e.g. NEAR uses 24) cause `18 - tokenDecimal` to underflow in checked math and the func"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/price-decimal-fix-assumes-decimals-le-18.yaml"
    WIKI_TITLE = "Price-decimal fix subtracts tokenDecimal from 18 with no `> 18` branch"
    WIKI_DESCRIPTION = "Pattern fires on bid/ask price-scaling helpers that perform `fixDecimal = 18 - tokenDecimal` and then `bidPrice / (10 ** fixDecimal)` (and / or `askPrice * (10 ** fixDecimal)`) without a separate branch for `tokenDecimal > 18`. The bug is silent for `tokenDecimal <= 18` (the common case) and DoSes the pricing path for any high-decimals token via the underflow on the subtraction."
    WIKI_EXPLOIT_SCENARIO = "DODOv3 lists a long-tail asset with 24 decimals via the standard `setTokenInfo` flow. The next call to `parseAllPrice` reverts inside the SafeMath subtraction `18 - 24`. Buy-side and sell-side both stop quoting that token. Liquidity providers who deposited the token cannot withdraw because the same path is used to compute their settlement price, locking funds until governance redeploys with a fixe"
    WIKI_RECOMMENDATION = "Branch explicitly: `if (tokenDecimal <= 18) { fixDecimal = 18 - tokenDecimal; price = price / (10**fixDecimal); } else { fixDecimal = tokenDecimal - 18; price = price * (10**fixDecimal); }`. Apply the inverse direction to the ask side. Optionally enforce `require(tokenDecimal <= 36)` to bound the mu"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'tokenDecimal|_decimals|\\.decimals\\(\\)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '\\b(uint\\d*\\s+)?fixDecimal\\s*=\\s*18\\s*-\\s*[A-Za-z_][A-Za-z0-9_]*\\s*;'}, {'function.body_contains_regex': '\\(\\s*10\\s*\\*\\*\\s*fixDecimal\\s*\\)'}, {'function.body_not_contains_regex': '[A-Za-z_][A-Za-z0-9_]*\\s*-\\s*18\\b|require\\s*\\([^)]*decimals?\\s*<=\\s*18\\s*\\)|if\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*>\\s*18\\s*\\)|tokenDecimal\\s*<\\s*18'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': False}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — price-decimal-fix-assumes-decimals-le-18: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
