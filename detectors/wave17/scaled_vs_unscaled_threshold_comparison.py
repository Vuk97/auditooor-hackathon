"""
scaled-vs-unscaled-threshold-comparison — generated from reference/patterns.dsl/scaled-vs-unscaled-threshold-comparison.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py scaled-vs-unscaled-threshold-comparison.yaml
Source: auditooor-R75-nethermind-uspd-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ScaledVsUnscaledThresholdComparison(AbstractDetector):
    ARGUMENT = "scaled-vs-unscaled-threshold-comparison"
    HELP = "A ratio-based safety check compares a scaled runtime value (e.g. getSystemCollateralizationRatio returning 11500 for 115%) to an unscaled constant named like MINIMUM_RATIO = 100 (intended as 100%). Because the constant is off by the scale factor, the check is effectively MIN=1%, silently disabling t"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/scaled-vs-unscaled-threshold-comparison.yaml"
    WIKI_TITLE = "Scaled ratio compared to unscaled minimum constant — safety check becomes a no-op"
    WIKI_DESCRIPTION = "Lending/stablecoin systems define thresholds like MINIMUM_COLLATERALIZATION_RATIO = 100 while helper functions return the ratio scaled by 10000 (BPS). `if (currentRatio < MINIMUM_COLLATERALIZATION_RATIO)` then compares e.g. 15000 < 100, always false — the unhealthy-system block is never entered. This is a systematic class of constant-scaling mismatches catalyzed by named constants whose comment sa"
    WIKI_EXPLOIT_SCENARIO = "USPD's unallocateStabilizerFunds sets MINIMUM_UNALLOCATE_COLLATERALIZATION_RATIO = 100 to mean 100%. getSystemCollateralizationRatio returns BPS-scaled (11500 for 115%). The guard `if (currentSystemRatio < 100) revert` only fires if systemRatio < 1%. A user can burn cUSPD and withdraw collateral while the system is severely undercollateralized (e.g., 50%), accelerating insolvency."
    WIKI_RECOMMENDATION = "Align the constant's scale to the helper return value (MINIMUM_... = 10000 for 100% in BPS, or 1e18 for 100% in wad). Add a one-liner unit test that asserts the constant in human-readable terms. Prefer storing thresholds as fractions of a named BASE constant (e.g. 100 * BPS) rather than magic number"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(CollateralizationRatio|HealthFactor|LTV|Ratio).*constant|constant.*(CollateralizationRatio|HealthFactor|LTV|Ratio)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(unallocate\\w*|allocate\\w*|_?burn\\w*|_?mint\\w*|_?withdraw\\w*|_?redeem\\w*|_?liquidate\\w*|_?check\\w*Health|_?checkCollat\\w*|_?checkRatio\\w*|_?validate\\w*Ratio|_?enforce\\w*Ratio|_?require\\w*Collat|_?assert\\w*Healthy|_?borrow\\w*|_?repay\\w*|_?deposit\\w*)'}, {'function.body_contains_regex': '\\b(10000|1e4|BPS|BASE|SCALE|1e18)\\b.*get[A-Z][a-zA-Z]*(Ratio|Rate|Factor)|get[A-Z][a-zA-Z]*(Ratio|Rate|Factor).*\\b(10000|1e4|BPS|BASE|SCALE|1e18)\\b'}, {'function.body_contains_regex': 'if\\s*\\(\\s*[a-zA-Z_0-9.()]+\\s*<\\s*MINIMUM_[A-Z_]+|if\\s*\\(\\s*[a-zA-Z_0-9.()]+\\s*<\\s*MIN_[A-Z_]+'}, {'function.body_not_contains_regex': 'MINIMUM_[A-Z_]+\\s*=\\s*(10000|1e4|11000|12000|15000|20000|100_?000|1e18)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — scaled-vs-unscaled-threshold-comparison: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
