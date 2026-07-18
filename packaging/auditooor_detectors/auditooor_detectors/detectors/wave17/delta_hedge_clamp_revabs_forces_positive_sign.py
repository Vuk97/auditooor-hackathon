"""
delta-hedge-clamp-revabs-forces-positive-sign — generated from reference/patterns.dsl/delta-hedge-clamp-revabs-forces-positive-sign.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delta-hedge-clamp-revabs-forces-positive-sign.yaml
Source: lisa-mine-r99-case-00486-cantina-smilee-finance-2024
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DeltaHedgeClampRevabsForcesPositiveSign(AbstractDetector):
    ARGUMENT = "delta-hedge-clamp-revabs-forces-positive-sign"
    HELP = "Delta-hedge function clamps `abs(tokensToSwap) > sideTokensAmount` (a sqrt-rounding tail case) by setting `tokensToSwap = revabs(sideTokensAmount, true)`. The hardcoded `true` second argument FORCES the result positive — so a negative `tokensToSwap` (vault needs to BUY side tokens) is silently flipp"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delta-hedge-clamp-revabs-forces-positive-sign.yaml"
    WIKI_TITLE = "Delta-hedge clamp uses `revabs(amount, true)` — flips sign of negative hedge"
    WIKI_DESCRIPTION = "Pattern fires on `deltaHedgeAmount`-style internal helpers that enter a clamp branch when `abs(tokensToSwap) > sideTokensAmount` and assign `tokensToSwap = SignedMath.revabs(sideTokensAmount, true);`. The second argument of `revabs` (or equivalent helper) is the desired sign of the result. Hardcoding `true` (positive) when the original `tokensToSwap` was negative inverts the hedge direction. The b"
    WIKI_EXPLOIT_SCENARIO = "A trader opens a short position large enough that the protocol must BUY 100 sideTokens to hedge. `tokensToSwap = -100` (negative meaning 'buy'). `abs(tokensToSwap) = 100 > sideTokensAmount = 99.5` (rounding tail), so the clamp branch fires. `revabs(99.5, true)` returns `+99.5`. The hedge engine sells 99.5 side tokens instead of buying 100. The protocol's net delta moves further from zero, not towa"
    WIKI_RECOMMENDATION = "Pass the sign of the original `tokensToSwap` to the clamp's `revabs` call: `tokensToSwap = SignedMath.revabs(sideTokensAmount, tokensToSwap >= 0);`. Equivalently, use a typed signed-int saturate helper that preserves the original sign on truncation. Add a property test that for every `(notionalUp, n"

    _PRECONDITIONS = [{'contract.has_function_matching': 'deltaHedgeAmount|hedgeAmount|computeHedge|positionDelta'}, {'contract.source_matches_regex': 'SignedMath\\.revabs|abs\\s*\\(\\s*tokensToSwap|sideTokensAmount'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'deltaHedgeAmount|hedgeAmount|computeHedge|computeDelta|_deltaHedge'}, {'function.body_contains_regex': 'revabs\\s*\\(\\s*[A-Za-z_][\\w\\.]*\\s*,\\s*true\\s*\\)'}, {'function.body_contains_regex': 'abs\\s*\\(\\s*tokensToSwap\\s*\\)\\s*>\\s*params\\.sideTokensAmount|abs\\s*\\(\\s*[A-Za-z_]+\\s*\\)\\s*>\\s*[A-Za-z_]+\\.sideTokensAmount'}, {'function.body_not_contains_regex': 'revabs\\s*\\(\\s*[A-Za-z_][\\w\\.]*\\s*,\\s*[A-Za-z_]\\w*\\s*>=\\s*0\\s*\\)|revabs\\s*\\(\\s*[A-Za-z_][\\w\\.]*\\s*,\\s*[A-Za-z_]\\w*\\s*<\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — delta-hedge-clamp-revabs-forces-positive-sign: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
