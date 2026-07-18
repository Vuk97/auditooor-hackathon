"""
r94-loop-eip712-domain-separator-immutable-forks-unsafe — generated from reference/patterns.dsl/r94-loop-eip712-domain-separator-immutable-forks-unsafe.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-eip712-domain-separator-immutable-forks-unsafe.yaml
Source: loop-cycle-81-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopEip712DomainSeparatorImmutableForksUnsafe(AbstractDetector):
    ARGUMENT = "r94-loop-eip712-domain-separator-immutable-forks-unsafe"
    HELP = "r94-loop-eip712-domain-separator-immutable-forks-unsafe"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-eip712-domain-separator-immutable-forks-unsafe.yaml"
    WIKI_TITLE = "r94-loop-eip712-domain-separator-immutable-forks-unsafe"
    WIKI_DESCRIPTION = "r94-loop-eip712-domain-separator-immutable-forks-unsafe"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-eip712-domain-separator-immutable-forks-unsafe"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'bytes32\\s+(public\\s+)?(immutable|constant)\\s+DOMAIN_SEPARATOR'}, {'contract.not_source_matches_regex': '(_domainSeparatorV4\\s*\\(|_buildDomainSeparator\\s*\\(|block\\.chainid\\s*==\\s*\\w*cachedChainId|if\\s*\\(\\s*block\\.chainid\\s*!=\\s*cachedChainId)'}]
    _MATCH = [{'contract.source_matches_regex': 'bytes32\\s+(public\\s+)?(immutable|constant)\\s+DOMAIN_SEPARATOR'}, {'function.source_matches_regex': '(ecrecover|_hashTypedData|DOMAIN_SEPARATOR)'}, {'function.not_source_matches_regex': '(?i)(mock|test|fixture|_domainSeparatorV4|block\\.chainid\\s*==\\s*\\w*cachedChainId)'}]

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
                info = [f, f" — r94-loop-eip712-domain-separator-immutable-forks-unsafe: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
