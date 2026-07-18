"""
round-to-zero-dust-bypass-no-guard — generated from reference/patterns.dsl/round-to-zero-dust-bypass-no-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py round-to-zero-dust-bypass-no-guard.yaml
Source: wave2-arithmetic-lift/round-to-zero-dust-cluster (mint-fee / ec-fee / dust-redeem / glider-solvency siblings)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RoundToZeroDustBypassNoGuard(AbstractDetector):
    ARGUMENT = "round-to-zero-dust-bypass-no-guard"
    HELP = "A fee / interest / proceeds quantity is computed as `amount * factor / DENOM` (multiply-then-floor-divide) and consumed with no zero-result guard. For a small enough `amount` the product is below DENOM and the whole quantity floors to 0, silently waiving the fee / skipping interest / burning shares "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/round-to-zero-dust-bypass-no-guard.yaml"
    WIKI_TITLE = "Round-to-zero dust bypass: `amount * factor / DENOM` with no zero-result guard"
    WIKI_DESCRIPTION = "Integer floor division truncates `amount * factor / DENOM` to 0 whenever `amount * factor < DENOM`. When the floored value is a fee, interest charge, or asset/share proceeds and the function does not revert (or otherwise guard) on a zero result, an attacker can choose inputs that zero the quantity: the fee is waived, the interest is skipped, or the caller redeems dust for nothing. The per-call los"
    WIKI_EXPLOIT_SCENARIO = "A vault charges `fee = amount * feeBps / 10000`. With `feeBps = 30` any `amount <= 333` yields `fee = 0`. An attacker (or a router batching many small transfers) loops the entry point with sub-threshold amounts and pays no fee at all, breaking the protocol's revenue invariant. The same shape on `interest = principal * rate / SCALE` lets dust borrowers accrue zero interest, and on `assets = shares "
    WIKI_RECOMMENDATION = "Guard the floored result: `require(fee > 0, \"dust\")` (or revert with `ZeroAmount` / `ZeroShares`), enforce a minimum input that cannot round the quantity to zero, or round the protocol-favoring side UP with `Math.mulDiv(a, b, c, Math.Rounding.Ceil)` so dust inputs cannot escape the charge. For ass"

    _PRECONDITIONS = [{'contract.source_matches_regex': '/\\s*(10000|1e\\d{1,2}|1_?000|SCALE|WAD|RAY|PRECISION|BPS|BASIS_?POINTS|_DENOM|DENOMINATOR|total[A-Z]\\w*|[A-Za-z_]*[Ss]upply)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\(?\\s*[\\w.\\[\\]]+\\s*\\*\\s*[\\w.\\[\\]]+\\s*\\)?\\s*/\\s*(10000|1e\\d{1,2}|1_?000|SCALE|WAD|RAY|PRECISION|BPS|BASIS_?POINTS|[A-Za-z_]*_DENOM\\w*|[A-Za-z_]*DENOMINATOR|total[A-Z]\\w*|[A-Za-z_]*[Ss]upply)\\b'}, {'function.body_contains_regex': '(?i)\\b(fee|interest|amount|amountOut|proceeds|payout|reward|rewards|shares|assets|out)\\b\\s*='}, {'function.body_contains_regex': '(?i)(\\b\\w+\\s*(?:\\[[^\\]]*\\])?\\s*(?:\\+=|-=)|[\\w.\\[\\]]+\\s*-\\s*(?:fee|interest|amount|proceeds|payout|reward))'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\(\\s*[\\w.\\[\\]]+\\s*(?:>\\s*0|>=\\s*1|!=\\s*0|>=\\s*[A-Z_]*MIN)|if\\s*\\(\\s*[\\w.\\[\\]]+\\s*==\\s*0\\s*\\)\\s*(?:revert|return)|revert\\s+Zero|ZeroAmount|ZeroShares|ZeroAssets|InsufficientOutput|mulDivUp|mulDivRoundingUp|ceilDiv|divUp|roundUp|Rounding\\.(Up|Ceil)|FullMath\\.mulDiv|Math\\.mulDiv|mulDivDown\\s*\\(|FixedPointMathLib)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" — round-to-zero-dust-bypass-no-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
