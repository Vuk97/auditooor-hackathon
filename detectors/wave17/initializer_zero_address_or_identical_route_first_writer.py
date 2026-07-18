"""
initializer-zero-address-or-identical-route-first-writer - generated from reference/patterns.dsl/initializer-zero-address-or-identical-route-first-writer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py initializer-zero-address-or-identical-route-first-writer.yaml
Source: Fire7 worker IF recall lift from initializer-front-run same-class misses; source-backed by bridge-route-allows-identical-source-and-destination-chainid and public-route-or-chain-migration-first-writer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitializerZeroAddressOrIdenticalRouteFirstWriter(AbstractDetector):
    ARGUMENT = "initializer-zero-address-or-identical-route-first-writer"
    HELP = "Public route initializer writes cross-domain route and endpoint state without caller binding, same-domain rejection, or zero-endpoint rejection."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/initializer-zero-address-or-identical-route-first-writer.yaml"
    WIKI_TITLE = "Public route initializer lets the first writer store a zero or self-route endpoint"
    WIKI_DESCRIPTION = "Bridge route setup often happens after deployment through `initialize*`, `configure*`, or `migrate*` functions. The dangerous first-writer shape accepts source and destination domain ids plus a remote gateway, peer, endpoint, bridge, or messenger address, writes those values into route state, and omits caller binding. If the same setup also omits source-vs-destination and zero-address endpoint guards, a mempool observer can win the setup race with a self-route or zero endpoint before the intended deployment transaction lands."
    WIKI_EXPLOIT_SCENARIO = "A bridge team deploys a route registry and plans to call `initializeBridgeRoute(10, 42161, realGateway)`. The function is public and writes `gatewayFor[source][destination] = gateway`. An attacker calls first with `initializeBridgeRoute(10, 10, address(0))` or another attacker-selected endpoint. The legitimate setup later reverts or overwrites through an already poisoned route, and downstream bridge sends resolve through a self-route or zero endpoint."
    WIKI_RECOMMENDATION = "Bind route setup to the intended actor with onlyFactory, onlyOwner, onlyGovernance, onlyRole, or an immutable deployer check. Reject source and destination domain equality and reject zero remote endpoint addresses before any persistent route write. Prefer factory-time initialization when possible so no untrusted caller can claim the post-deploy route namespace."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|route|path|peer|remote|endpoint|domain|eid|chain|registry|messenger|migrat|initialize|init)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(initialize|init|setup|bootstrap|configure|register|create|add|set|migrate)[A-Z]\\w*(Route|Path|Chain|Domain|Eid|Endpoint|Peer|Remote|Gateway|Bridge|Lane|Registry)$|^(configureRoute|setRoute|registerRoute|registerPath|registerChain|setPeer|setRemoteBridge|setRemoteGateway|setEndpoint|setTrustedRemote|migrateToGateway|migrateChainToGateway|initializeBridge)$'}, {'function.has_param_of_type': 'address'}, {'function.source_matches_regex': '(?i)\\b(source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\b'}, {'function.source_matches_regex': '(?i)\\b(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)\\b'}, {'function.source_matches_regex': '(?i)(remoteGateway|remoteBridge|gateway|peer|counterpart|trustedRemote|endpoint|router|bridge|messenger)'}, {'function.body_contains_regex': '(?i)((source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\s*=\\s*_?(source|src|origin|from|local)\\w*|(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)\\s*=\\s*_?(destination|dest|dst|remote|target|to)\\w*|routes?\\s*\\[[^;{}]+\\]\\s*\\[[^;{}]+\\]\\s*=|gatewayFor\\s*\\[[^;{}]+\\]\\s*\\[[^;{}]+\\]\\s*=)'}, {'function.body_contains_regex': '(?i)((remoteGateway|remoteBridge|gateway|peer|counterpart|trustedRemote|endpoint|router|bridge|messenger)\\w*\\s*=\\s*_?\\w+|routes?\\s*\\[[^;{}]+\\]\\s*\\[[^;{}]+\\]\\s*=\\s*_?\\w+|gatewayFor\\s*\\[[^;{}]+\\]\\s*\\[[^;{}]+\\]\\s*=\\s*_?\\w+)'}, {'function.has_modifier_not': 'onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|onlyRole|onlyBridgeAdmin|onlyProxy'}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|onlyRole|onlyBridgeAdmin|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))|if\\s*\\(\\s*msg\\.sender\\s*!=\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))\\s*\\)\\s*revert|_checkOwner\\s*\\(|_checkRole\\s*\\(|hasRole\\s*\\(|AccessControl|Ownable|_authorize)'}, {'function.body_not_contains_regex': '(?i)(SameChain|SameDomain|SameEid|InvalidSameChain|InvalidSameDomain|InvalidSameEid|sourceChainId\\s*==\\s*destinationChainId|destinationChainId\\s*==\\s*sourceChainId|_sourceChainId\\s*==\\s*_destinationChainId|_destinationChainId\\s*==\\s*_sourceChainId|srcEid\\s*==\\s*dstEid|dstEid\\s*==\\s*srcEid|sourceDomain\\s*==\\s*destinationDomain|destinationDomain\\s*==\\s*sourceDomain|require\\s*\\(\\s*_?(source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\s*!=\\s*_?(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)|if\\s*\\(\\s*_?(source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\s*==\\s*_?(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)\\s*\\)\\s*revert)'}, {'function.body_not_contains_regex': '(?i)(Zero(Address|Gateway|Peer|Remote|Endpoint)|AddressZero|Invalid(Gateway|Peer|Remote|Endpoint)|require\\s*\\(\\s*_?\\w*(gateway|peer|remote|endpoint|router|bridge|messenger)\\w*\\s*!=\\s*address\\s*\\(\\s*0x?0*\\s*\\)|if\\s*\\(\\s*_?\\w*(gateway|peer|remote|endpoint|router|bridge|messenger)\\w*\\s*==\\s*address\\s*\\(\\s*0x?0*\\s*\\)\\s*\\)\\s*revert)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|example)\\b'}]

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
                info = [f, f" - initializer-zero-address-or-identical-route-first-writer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
