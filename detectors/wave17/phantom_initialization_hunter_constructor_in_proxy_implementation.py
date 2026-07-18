"""
phantom-initialization-hunter-constructor-in-proxy-implementation — generated from reference/patterns.dsl/phantom-initialization-hunter-constructor-in-proxy-implementation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py phantom-initialization-hunter-constructor-in-proxy-implementation.yaml
Source: Hexens Glider query: logic-contract-takeover-via-unprotected-initialize
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PhantomInitializationHunterConstructorInProxyImplementation(AbstractDetector):
    ARGUMENT = "phantom-initialization-hunter-constructor-in-proxy-implementation"
    HELP = "Fixture-smoke heuristic for proxy implementations that assign proxy-relevant state in a constructor while exposing an initializer."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/phantom-initialization-hunter-constructor-in-proxy-implementation.yaml"
    WIKI_TITLE = "Phantom Initialization Hunter (Constructor in Proxy Implementation)"
    WIKI_DESCRIPTION = "A proxy implementation constructor writes owner/admin/configuration state, but proxy deployments do not execute implementation constructors in proxy storage. This row currently proves only the owned fixture pair."
    WIKI_EXPLOIT_SCENARIO = "A logic contract constructor assigns owner and treasury state. When deployed behind a proxy, the proxy storage remains unset because only the implementation storage received those assignments."
    WIKI_RECOMMENDATION = "Move proxy storage initialization into initialize/reinitialize functions and use the constructor only for implementation-local setup such as disabling initializers. This row remains NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.has_function_matching': '^(?:initialize|initializeV\\d+|__\\w+_init(?:_unchained)?)$'}]
    _MATCH = [{'function.is_constructor': True}, {'function.writes_storage_matching': '(?:^|_)(?:owner|admin|governance|governor|guardian|operator|authority|manager|controller|treasury|feeRecipient|implementation|registry|oracle|token|asset)(?:$|_)'}, {'function.not_source_matches_regex': '\\b_disableInitializers\\s*\\('}]

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
                info = [f, f" — phantom-initialization-hunter-constructor-in-proxy-implementation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
