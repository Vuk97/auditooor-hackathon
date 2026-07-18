"""
bridge-permissionless-route-setter-frontrun-lock - generated from reference/patterns.dsl/bridge-permissionless-route-setter-frontrun-lock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-permissionless-route-setter-frontrun-lock.yaml
Source: auditooor-realworld-recall initializer-front-run start-with bridge-route-allows-identical-source-and-destination-chainid
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgePermissionlessRouteSetterFrontrunLock(AbstractDetector):
    ARGUMENT = "bridge-permissionless-route-setter-frontrun-lock"
    HELP = "Bridge route or peer setter is one-shot and permissionless. An attacker can front-run deployment setup, store an attacker-controlled remote endpoint, and permanently wedge or hijack the lane."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-permissionless-route-setter-frontrun-lock.yaml"
    WIKI_TITLE = "Bridge route or peer setter is permissionless one-shot and front-runnable"
    WIKI_DESCRIPTION = "Cross-chain adapters often deploy in two phases: contract creation first, route or peer wiring second. A dangerous shape appears when the second phase is implemented as a public setter that relies only on an unset sentinel such as `require(peer == address(0))` or `require(routes[src][dst] == address(0))`. Because there is no deployer, owner, governance, or factory binding, any mempool observer can"
    WIKI_EXPLOIT_SCENARIO = "Team deploys a bridge route registry and plans to call `configureRoute(1, 10, realRemoteGateway)` in the next transaction. The contract exposes `configureRoute` publicly and only checks `routes[src][dst] == address(0)`. A watcher front-runs with `configureRoute(1, 10, attackerGateway)`. Their transaction writes first, the route slot is now occupied, and the legitimate setup reverts. Every packet f"
    WIKI_RECOMMENDATION = "Bind the first write to an authorized actor: `onlyOwner`, `onlyFactory`, or an immutable deployer set in the constructor. Better, pass the peer or remote route target in the constructor so there is no post-deploy race at all. For mutable route registries, separate one-time deployment wiring from nor"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|tunnel|route|path|peer|counterpart)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(set|configure|register|initialize)[A-Z]\\w*(Peer|Counterpart|Remote|Route|Path|Bridge|Tunnel|Gateway)$|^(setPeer|setCounterpart|setRemoteBridge|setRemoteGateway|configureRoute|registerRoute|registerPath|initializeBridge)$'}, {'function.has_modifier_not': 'onlyOwner|onlyAdmin|onlyGovernance|onlyFactory|onlyRole|onlyProxy'}, {'function.source_matches_regex': '(?i)(peer|counterpart|remoteGateway|remoteBridge|fxRootTunnel|fxChildTunnel|route)'}, {'function.body_contains_regex': '(?i)(require|if)\\s*\\(\\s*[^;{}]*(peer|counterpart|remoteGateway|remoteBridge|fxRootTunnel|fxChildTunnel|routes?\\s*\\[[^]]+\\]\\s*\\[[^]]+\\])\\s*==\\s*address\\s*\\(\\s*0x?0?\\s*\\)'}, {'function.body_contains_regex': '(?i)(peer|counterpart|remoteGateway|remoteBridge|fxRootTunnel|fxChildTunnel)\\s*=\\s*_?\\w+|routes?\\s*\\[[^]]+\\]\\s*\\[[^]]+\\]\\s*=\\s*_?\\w+'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*msg\\.sender\\s*==\\s*(_?(owner|admin|deployer|factory)|owner\\(\\)|admin\\(\\))|if\\s*\\(\\s*msg\\.sender\\s*!=\\s*(_?(owner|admin|deployer|factory)|owner\\(\\)|admin\\(\\))\\s*\\)\\s*revert|_checkOwner\\s*\\(|_authorize|hasRole\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - bridge-permissionless-route-setter-frontrun-lock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
