"""
initializer-first-writer-route-fire13 - generated from reference/patterns.dsl/initializer-first-writer-route-fire13.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py initializer-first-writer-route-fire13.yaml
Source: Fire13 SI recall lift from initializer-front-run same-class misses; source-backed by a-newly-created-chain-that-has-been-migrated-to-the-gateway-will, public-route-or-chain-migration-first-writer, and bridge-route-allows-identical-source-and-destination-chainid
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitializerFirstWriterRouteFire13(AbstractDetector):
    ARGUMENT = "initializer-first-writer-route-fire13"
    HELP = "Public bridge or gateway setup finalizes migration or route state without the refresh, caller-binding, same-domain, or zero-endpoint guards required for safe first-writer initialization."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/initializer-first-writer-route-fire13.yaml"
    WIKI_TITLE = "First public bridge route writer can finalize stale or unsafe migration state"
    WIKI_DESCRIPTION = "Bridge and gateway deployments often wire route or migration state after deployment. The unsafe shape is a public setup or migration consumer that either reads migrated gateway state without refreshing the priority tree snapshot, or writes route and endpoint state from calldata without caller binding plus source-vs-destination and zero-endpoint guards. A first public caller can win the setup race, finalize stale migration state, or lock the route namespace into an unsafe endpoint."
    WIKI_EXPLOIT_SCENARIO = "A gateway migration is staged with forwarded bridge burn state and historical roots. The public `priorityTree()` path reads those fields and writes `gatewayReturnQueued` without calling the refresh helper, so a migrated chain can be finalized from stale state. In the route setup sibling, an attacker front-runs `initializeBridgeRoute(src, dst, gateway)` and stores a self-route or attacker-selected gateway before the intended setup transaction lands."
    WIKI_RECOMMENDATION = "Route and gateway setup should be caller-bound to the factory, deployer, governance, or role holder. Refresh migrated gateway state before consuming priority-tree or historical-root state. Reject source and destination equality and zero endpoints before writing route state. Prefer factory-time initialization so no untrusted caller can win a post-deploy setup race."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|route|path|peer|remote|endpoint|domain|chain|migrat|priorityTree|historicalRoots|forwardedBridgeBurn)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(priorityTree|startIndex|initialize|init|setup|bootstrap|configure|register|create|add|set|migrate)\\w*(Route|Path|Chain|Gateway|Bridge|Migration)?$|^(configureRoute|registerRoute|migrateChainToGateway|migrateToGateway|initializeBridgeRoute)$'}, {'function.source_matches_regex': '(?i)(forwardedBridgeBurn|historicalRoots|gatewayFor|routeCreated|migratedChains|routes?\\s*\\[|sourceChainId|destinationChainId|remoteGateway|remoteBridge|gateway)'}, {'function.body_contains_regex': '(?i)(gatewayReturnQueued\\s*=|gatewayFor\\s*\\[[^;{}]+\\]\\s*(\\[[^;{}]+\\])?\\s*=|routes?\\s*\\[[^;{}]+\\]\\s*(\\[[^;{}]+\\])?\\s*=|routeCreated\\s*\\[[^;{}]+\\]\\s*=|migratedChains\\s*\\[[^;{}]+\\]\\s*=|(source|src)\\w*ChainId\\s*=\\s*_?(source|src)\\w*ChainId|(destination|dest|dst|remote|target|to)\\w*ChainId\\s*=\\s*_?(destination|dest|dst|remote|target|to)\\w*ChainId|remoteGateway\\s*=\\s*_?\\w+|remoteBridge\\s*=\\s*_?\\w+)'}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|onlyRole|onlyBridgeAdmin|require\\s*\\(\\s*msg\\.sender\\s*==|if\\s*\\(\\s*msg\\.sender\\s*!=|_checkOwner\\s*\\(|_checkRole\\s*\\(|hasRole\\s*\\(|AccessControl|Ownable|_authorize|_?update\\w*\\s*\\(|_?refresh\\w*\\s*\\(|_?sync\\w*\\s*\\(|_?validate\\w*\\s*\\(|_?check\\w*\\s*\\(|SameChain|SameDomain|SameEid|InvalidSameChain|InvalidChain|ZeroGateway|ZeroRemote|ZeroEndpoint|AddressZero|sourceChainId\\s*==\\s*destinationChainId|destinationChainId\\s*==\\s*sourceChainId|_sourceChainId\\s*==\\s*_destinationChainId|_destinationChainId\\s*==\\s*_sourceChainId|require\\s*\\(\\s*_?(source|src|origin|from|local)\\w*(ChainId|Eid|Domain(Id)?)\\s*!=\\s*_?(destination|dest|dst|remote|target|to)\\w*(ChainId|Eid|Domain(Id)?)|address\\s*\\(\\s*0\\s*\\)\\s*!=|!=\\s*address\\s*\\(\\s*0\\s*\\))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|example)\\b'}]

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
                info = [f, f" - initializer-first-writer-route-fire13: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
