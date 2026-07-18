"""
library-zero-address-return-unchecked — generated from reference/patterns.dsl/library-zero-address-return-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py library-zero-address-return-unchecked.yaml
Source: solodit-cluster/C0246
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LibraryZeroAddressReturnUnchecked(AbstractDetector):
    ARGUMENT = "library-zero-address-return-unchecked"
    HELP = "External function writes the address return of a library/factory lookup (SyntLib.getRepresentation, factoryOf, _getSynt, getToken, getMapping) into storage without checking for address(0) — silent misconfiguration."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/library-zero-address-return-unchecked.yaml"
    WIKI_TITLE = "Unchecked address(0) return from library/factory lookup"
    WIKI_DESCRIPTION = "A library or factory helper declared to return `address` is allowed to return `address(0)` as a sentinel for missing-mapping / not-yet-deployed / lookup-miss. The caller assigns the return value directly into a storage slot without a zero-address check. Downstream code then either reverts (permanent DoS) or — worse — treats the zero slot as a valid uninitialised sentinel and routes messages / toke"
    WIKI_EXPLOIT_SCENARIO = "A cross-chain bridge calls `SyntLib.getRepresentation(fromChain, token)` to look up the local wrapper for a foreign token. When the wrapper has not yet been deployed the library returns `address(0)`. The bridge assigns `wrapperOf[fromChain][token] = SyntLib.getRepresentation(fromChain, token);` without a zero check. A subsequent `bridgeIn` call invokes `IERC20(wrapperOf[...]).mint(user, amount)` w"
    WIKI_RECOMMENDATION = "After every library / factory / mapping lookup whose return type is `address`, require the result is non-zero before writing it to storage or passing it to an external call: `address repr = SyntLib.getRepresentation(...); require(repr != address(0), \"missing representation\"); wrapperOf[...] = repr"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.body_contains_regex': 'SyntLib\\.getRepresentation|_getSynt|getMapping\\s*\\(|mapping\\s*\\(.*\\)\\s*public|getToken\\s*\\(|factoryOf\\s*\\('}, {'function.body_contains_regex': '=\\s*(SyntLib|\\.getRepresentation|factoryOf|_getSynt)'}, {'function.body_not_contains_regex': 'require\\s*\\(.*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\(.*==\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — library-zero-address-return-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
