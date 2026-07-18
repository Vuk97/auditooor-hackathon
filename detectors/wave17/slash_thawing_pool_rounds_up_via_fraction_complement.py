"""
slash-thawing-pool-rounds-up-via-fraction-complement — generated from reference/patterns.dsl/slash-thawing-pool-rounds-up-via-fraction-complement.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py slash-thawing-pool-rounds-up-via-fraction-complement.yaml
Source: auditooor-R107-thegraph-Trust-H-4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SlashThawingPoolRoundsUpViaFractionComplement(AbstractDetector):
    ARGUMENT = "slash-thawing-pool-rounds-up-via-fraction-complement"
    HELP = "A slashing / penalty / fee-deduction function reduces a proportional storage variable using `state = state * (T - X) / T`. Solidity's integer division rounds the result of `(state * (T - X))` DOWN, but the algebraic equivalent `state *= (1 - X/T)` should round the result DOWN only when `X/T` is roun"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/slash-thawing-pool-rounds-up-via-fraction-complement.yaml"
    WIKI_TITLE = "Slashing reduces proportional state via `state * (T - X) / T` — implicit round-up of (1 - X/T)"
    WIKI_DESCRIPTION = "When slashing a delegation pool / provision / fee-vault, protocols often want to keep an internal counter (e.g. `tokensThawing` or `pendingFees`) proportionally consistent with the pool size after the slash. The naive arithmetic `state = state * (T - X) / T` looks symmetric but the integer division at the end rounds DOWN, which means the implicit `(1 - X/T)` factor rounds UP relative to a separate"
    WIKI_EXPLOIT_SCENARIO = "Initial state `tokens = tokensThawing = 1e18 + 1`. A 1-wei slash is processed: `slashFraction = (1 * 1e18) / (1e18 + 1) = 0` (rounds down to 0); `tokens = (1e18 + 1) - 1 = 1e18`; `tokensThawing = (1e18 + 1) * (1e18 - 0) / 1e18 = 1e18 + 1`. Now `tokensThawing > tokens`. The very last delegator who tries to `withdraw()` triggers `pool.tokens -= tokensThawed` which underflows — the entire delegation "
    WIKI_RECOMMENDATION = "Use ceiling-rounding for the numerator that should round up, or compute the complement explicitly. One safe form: `state = mulDiv(state, T - X, T, Math.Rounding.Down)` paired with `slashFraction = mulDiv(X, SCALE, T, Math.Rounding.Up)` so the two formulas round in the same direction. Alternatively r"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(slash|penali[sz]e|withdraw|deprovision|decay|reduce|burn)\\w*$'}, {'function.body_contains_regex': '(\\w+(?:\\.\\w+)?)\\s*=\\s*\\(\\s*\\1\\s*\\*\\s*\\(\\s*(\\w+(?:\\.\\w+)?)\\s*-\\s*\\w+(?:\\.\\w+)?\\s*\\)\\s*\\)\\s*/\\s*\\2'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — slash-thawing-pool-rounds-up-via-fraction-complement: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
