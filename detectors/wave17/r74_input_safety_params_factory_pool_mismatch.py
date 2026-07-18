"""
r74-input-safety-params-factory-pool-mismatch — generated from reference/patterns.dsl/r74-input-safety-params-factory-pool-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-input-safety-params-factory-pool-mismatch.yaml
Source: r74b-cross-firm-cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74InputSafetyParamsFactoryPoolMismatch(AbstractDetector):
    ARGUMENT = "r74-input-safety-params-factory-pool-mismatch"
    HELP = "Pool initialize() / setParams() writes safety parameters without enforcing the same bounds the factory applied; direct-init paths bypass fee/A/gamma validation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-input-safety-params-factory-pool-mismatch.yaml"
    WIKI_TITLE = "Pool initialize bypasses factory-enforced parameter bounds"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Complex AMMs (Curve Tricrypto, Balancer Composable Stable, Velodrome v2) parameterize each pool with amplification, fee, gamma, and decimals tuples that have non-trivial interaction bounds. When the factory's createPool validates these bounds but the pool's own initialize/setParams does not re-check, any path that reaches initialize without "
    WIKI_EXPLOIT_SCENARIO = "A team deploys a new Tricrypto-NG pool via a scripted direct-clone (not the factory, because they want a custom admin). They forget to call the factory's parameter-validation helper. The pool's initialize accepts gamma = 1e15 (below MIN_GAMMA = 1e18). The math library's internal iterations do not converge for that gamma and every swap reverts — but only after liquidity has been deposited. Deposito"
    WIKI_RECOMMENDATION = "Pool initialize() must apply the full suite of factory parameter validations regardless of caller — do not optimize them away on the assumption that 'factory already checked.' Use a shared library: `ParamValidator.validate(feeBps, A, gamma, decimals)` called unconditionally from both the factory's c"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(factory|Factory|createPool|deployPool|initialize)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(initialize|init|_initialize|createPool|deployPool|setParams)$'}, {'function.writes_storage_matching': '(fee|A|gamma|ampCoefficient|decimals|tokenDecimals|thresh|weight)'}, {'function.body_not_contains_regex': 'MIN_FEE|MAX_FEE|MIN_A|MAX_A|MIN_GAMMA|MAX_GAMMA|require\\s*\\([^)]*fee\\s*<=?\\s*MAX|require\\s*\\([^)]*fee\\s*>=?\\s*MIN'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-input-safety-params-factory-pool-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
