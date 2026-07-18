"""
initializer-route-or-domain-first-writer-takeover - generated from reference/patterns.dsl/initializer-route-or-domain-first-writer-takeover.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py initializer-route-or-domain-first-writer-takeover.yaml
Source: rwrq-initializer-front-run-1c1f2e520280; confirmed corpus samples bridge-route-allows-identical-source-and-destination-chainid and public-route-or-chain-migration-first-writer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitializerRouteOrDomainFirstWriterTakeover(AbstractDetector):
    ARGUMENT = "initializer-route-or-domain-first-writer-takeover"
    HELP = "Public route or domain setup writes source and destination domain ids plus a remote endpoint without caller binding or same-domain validation."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/initializer-route-or-domain-first-writer-takeover.yaml"
    WIKI_TITLE = "Public route or domain initializer lets the first writer control remote endpoint state"
    WIKI_DESCRIPTION = "Bridge and cross-chain adapters often configure route state after deployment. The risky shape is a public setup, configure, register, initialize, or migrate function that stores source and destination chain, endpoint, or domain ids plus a gateway, peer, endpoint, bridge, or messenger address from caller-supplied arguments. Without factory, deployer, governance, owner, or role binding, the first setup caller can claim the route namespace. Without a same-domain guard, the caller can also collapse the route onto the same chain or endpoint. Without a remote endpoint zero-address guard, an unset or zero endpoint can brick later message delivery."
    WIKI_EXPLOIT_SCENARIO = "A team deploys a route registry and plans to call configureRoute(sourceChainId=10, destinationChainId=42161, remoteGateway=realGateway). The function is public and writes sourceChainId, destinationChainId, and remoteGateway directly from calldata. A mempool observer calls configureRoute(10, 10, attackerGateway) first. The registry now points the route to an attacker-selected or degenerate same-domain endpoint, and downstream bridge sends resolve through that route state instead of the intended remote gateway."
    WIKI_RECOMMENDATION = "Bind route and domain setup to the intended actor with onlyFactory, onlyOwner, onlyGovernance, onlyRole, or an immutable deployer check. Reject source and destination domain equality, zero chain or endpoint ids where applicable, and zero remote endpoint addresses before writing persistent route state. Prefer constructor or factory-time route wiring when possible so no untrusted caller can win a post-deploy setup race."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|route|path|peer|remote|endpoint|domain|eid|chain|registry|messenger|migrat|initialize|init)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(initialize|init|setup|bootstrap|configure|register|create|add|set|migrate)[A-Z]\\w*(Route|Path|Chain|Domain|Eid|Endpoint|Peer|Remote|Gateway|Bridge|Lane|Registry)$|^(configureRoute|setRoute|registerRoute|registerPath|registerChain|setPeer|setRemoteBridge|setRemoteGateway|setEndpoint|setTrustedRemote|migrateToGateway|migrateChainToGateway|initializeBridge)$'}, {'function.has_param_of_type': 'address'}, {'function.source_matches_regex': '(?i)\\b(source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\b'}, {'function.source_matches_regex': '(?i)\\b(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)\\b'}, {'function.source_matches_regex': '(?i)(remoteGateway|remoteBridge|gateway|peer|counterpart|trustedRemote|endpoint|router|bridge|messenger)'}, {'function.body_contains_regex': '(?i)((source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\s*=\\s*_?(source|src|origin|from|local)\\w*|(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)\\s*=\\s*_?(destination|dest|dst|remote|target|to)\\w*|routes?\\s*\\[[^;{}]+\\]\\s*=|gatewayFor\\s*\\[[^;{}]+\\]\\s*=)'}, {'function.body_contains_regex': '(?i)((remoteGateway|remoteBridge|gateway|peer|counterpart|trustedRemote|endpoint|router|bridge|messenger)\\w*\\s*=\\s*_?\\w+|routes?\\s*\\[[^;{}]+\\]\\s*=\\s*_?\\w+|gatewayFor\\s*\\[[^;{}]+\\]\\s*=\\s*_?\\w+)'}, {'function.has_modifier_not': 'onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|onlyRole|onlyBridgeAdmin|onlyProxy'}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|onlyRole|onlyBridgeAdmin|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))|if\\s*\\(\\s*msg\\.sender\\s*!=\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))\\s*\\)\\s*revert|_checkOwner\\s*\\(|_checkRole\\s*\\(|hasRole\\s*\\(|AccessControl|Ownable|_authorize)'}, {'function.body_not_contains_regex': '(?i)(SameChain|SameDomain|SameEid|InvalidSameChain|InvalidSameDomain|InvalidSameEid|sourceChainId\\s*==\\s*destinationChainId|destinationChainId\\s*==\\s*sourceChainId|_sourceChainId\\s*==\\s*_destinationChainId|_destinationChainId\\s*==\\s*_sourceChainId|srcEid\\s*==\\s*dstEid|dstEid\\s*==\\s*srcEid|sourceDomain\\s*==\\s*destinationDomain|destinationDomain\\s*==\\s*sourceDomain|require\\s*\\(\\s*_?(source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\s*!=\\s*_?(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)|if\\s*\\(\\s*_?(source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\s*==\\s*_?(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)\\s*\\)\\s*revert)'}, {'function.body_not_contains_regex': '(?i)(Zero(Address|Gateway|Peer|Remote|Endpoint)|AddressZero|Invalid(Gateway|Peer|Remote|Endpoint)|require\\s*\\(\\s*_?\\w*(gateway|peer|remote|endpoint|router|bridge|messenger)\\w*\\s*!=\\s*address\\s*\\(\\s*0x?0*\\s*\\)|if\\s*\\(\\s*_?\\w*(gateway|peer|remote|endpoint|router|bridge|messenger)\\w*\\s*==\\s*address\\s*\\(\\s*0x?0*\\s*\\)\\s*\\)\\s*revert)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|example)\\b'}]

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
                info = [f, f" - initializer-route-or-domain-first-writer-takeover: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
