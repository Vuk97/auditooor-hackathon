"""
insufficient-equilibrium-fee-pool-can-cause-swaps-to-fail — generated from reference/patterns.dsl/insufficient-equilibrium-fee-pool-can-cause-swaps-to-fail.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py insufficient-equilibrium-fee-pool-can-cause-swaps-to-fail.yaml
Source: zellic audit LayerZero Stargate - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InsufficientEquilibriumFeePoolCanCauseSwapsToFail(AbstractDetector):
    ARGUMENT = "insufficient-equilibrium-fee-pool-can-cause-swaps-to-fail"
    HELP = "A `swap` path subtracts `eqReward` from `eqFeePool` without visibly capping the reward to the available pool."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/insufficient-equilibrium-fee-pool-can-cause-swaps-to-fail.yaml"
    WIKI_TITLE = "Insufficient equilibrium fee pool can cause swaps to fail"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only that the owned fixture pair separates a visible `eqFeePool - eqReward` subtraction from a local variant that clamps the reward first. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A `swap` path subtracts `eqReward` from `eqFeePool` without visibly capping the reward to the available pool."
    WIKI_RECOMMENDATION = "Clamp `eqReward` to the available `eqFeePool` or short-circuit before subtraction. Do not promote from this fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(swap|eqReward|eqFeePool|stopSwap)'}]
    _MATCH = [{'function.name_matches': '^swap$'}, {'function.body_contains_regex': '(?i)\\beqReward\\b'}, {'function.body_contains_regex': '(?i)\\beqFeePool\\b'}, {'function.body_contains_regex': '(?i)\\beqFeePool\\s*=\\s*eqFeePool\\s*-\\s*[^;{}]*\\beqReward\\b|\\beqFeePool\\s*-=\\s*[^;{}]*\\beqReward\\b|\\beqFeePool\\s*=\\s*eqFeePool\\s*\\.sub\\s*\\([^;{}]*\\beqReward\\b[^;{}]*\\)'}, {'function.body_not_contains_regex': '(?is)(?:Math\\.min|min|_min)\\s*\\(\\s*eqFeePool\\s*,\\s*[^;{}]*\\beqReward\\b[^;{}]*\\)|(?:Math\\.min|min|_min)\\s*\\(\\s*[^;{}]*\\beqReward\\b[^;{}]*,\\s*eqFeePool\\s*\\)|if\\s*\\([^;{}]*\\beqReward\\b\\s*>\\s*eqFeePool[^;{}]*\\)\\s*\\{?[^{}]*?\\beqReward\\b\\s*=\\s*eqFeePool\\b|if\\s*\\([^;{}]*eqFeePool\\s*<\\s*[^;{}]*\\beqReward\\b[^;{}]*\\)\\s*\\{?[^{}]*?\\beqReward\\b\\s*=\\s*eqFeePool\\b'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — insufficient-equilibrium-fee-pool-can-cause-swaps-to-fail: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
