"""
r94-loop-chainid-cached-at-deploy-fork-replay — generated from reference/patterns.dsl/r94-loop-chainid-cached-at-deploy-fork-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-chainid-cached-at-deploy-fork-replay.yaml
Source: solodit-17657-trailofbits-eqlc-advanced-blockchain
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopChainidCachedAtDeployForkReplay(AbstractDetector):
    ARGUMENT = "r94-loop-chainid-cached-at-deploy-fork-replay"
    HELP = "r94-loop-chainid-cached-at-deploy-fork-replay"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-chainid-cached-at-deploy-fork-replay.yaml"
    WIKI_TITLE = "r94-loop-chainid-cached-at-deploy-fork-replay"
    WIKI_DESCRIPTION = "r94-loop-chainid-cached-at-deploy-fork-replay"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-chainid-cached-at-deploy-fork-replay"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(EIP712|DomainSeparator|Permit|ERC2612|ChainIdCache)', 'function.name_matches': '(?i)(constructor|initialize|init|setup|deployInit|initDomain|initializeEIP712)'}
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.source_matches_regex': '(_CACHED_CHAIN_ID\\s*=\\s*block\\.chainid|_CACHED_CHAIN_ID\\s*=\\s*\\w*chainId|DOMAIN_SEPARATOR\\s*=\\s*keccak\\w*\\s*\\(\\s*[^)]*chainid)'}, {'function.not_source_matches_regex': '(_domainSeparatorV4|_buildDomainSeparator|if\\s*\\(\\s*block\\.chainid\\s*!=\\s*_CACHED_CHAIN_ID|rebuildDomainSeparator|recomputeDomain|chainIdChanged|reinitializeDomain)'}, {'function.body_not_contains_regex': 'block\\.chainid\\s*==\\s*_CACHED_CHAIN_ID|block\\.chainid\\s*!=\\s*_CACHED_CHAIN_ID'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — r94-loop-chainid-cached-at-deploy-fork-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
