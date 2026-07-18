"""
r94-loop-user-supplied-domain-separator-cross-chain-replay — generated from reference/patterns.dsl/r94-loop-user-supplied-domain-separator-cross-chain-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-user-supplied-domain-separator-cross-chain-replay.yaml
Source: solodit-56703-c4-next-generation-forwarder
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopUserSuppliedDomainSeparatorCrossChainReplay(AbstractDetector):
    ARGUMENT = "r94-loop-user-supplied-domain-separator-cross-chain-replay"
    HELP = "r94-loop-user-supplied-domain-separator-cross-chain-replay"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-user-supplied-domain-separator-cross-chain-replay.yaml"
    WIKI_TITLE = "r94-loop-user-supplied-domain-separator-cross-chain-replay"
    WIKI_DESCRIPTION = "r94-loop-user-supplied-domain-separator-cross-chain-replay"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-user-supplied-domain-separator-cross-chain-replay"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(Forwarder|MetaTx|EIP712|ERC2771|RelayedCall)', 'function.name_matches': '(?i)(forward|executeMeta|relayedForward|permitAndCall|metaTxCall)', 'function.source_matches_regex': '(domainSeparator\\s*:\\s*bytes32\\s+\\w+|bytes32\\s+\\w*domainSeparator\\w*\\s*,|bytes32\\s+\\w*ds\\b)', 'function.not_source_matches_regex': '(DOMAIN_SEPARATOR\\s*\\(\\s*\\)|_domainSeparatorV4\\s*\\(\\s*\\)|this\\.domainSeparator\\s*\\(\\s*\\)|eip712Domain)'}
    _MATCH = ['contract.source_matches_regex', 'function.name_matches', 'function.source_matches_regex', 'function.not_source_matches_regex']

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
                info = [f, f" — r94-loop-user-supplied-domain-separator-cross-chain-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
