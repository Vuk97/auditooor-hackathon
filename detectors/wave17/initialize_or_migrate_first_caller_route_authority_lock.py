"""
initialize-or-migrate-first-caller-route-authority-lock - generated from reference/patterns.dsl/initialize-or-migrate-first-caller-route-authority-lock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py initialize-or-migrate-first-caller-route-authority-lock.yaml
Source: auditooor.vault_realworld_recall_gap_priorities.v1:f22f2ff716254f7a initializer-front-run sibling lift
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitializeOrMigrateFirstCallerRouteAuthorityLock(AbstractDetector):
    ARGUMENT = "initialize-or-migrate-first-caller-route-authority-lock"
    HELP = "A public initialize/setup/register/migrate path writes owner/admin, peer, chain, gateway, or bridge-route state behind only a first-write guard. Without factory, deployer, or governance binding, the first caller can front-run deployment or migration and lock in attacker-controlled authority or remot"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/initialize-or-migrate-first-caller-route-authority-lock.yaml"
    WIKI_TITLE = "First-caller initialize or migration setup locks authority, chain, or route state"
    WIKI_DESCRIPTION = "Some deployments wire critical state in a second transaction after contract creation or after a migration step. The dangerous shape is a public `initialize*`, `setup*`, `register*`, or `migrate*` entrypoint that stores long-lived authority (`owner`, `admin`, roles), remote peer state (`peer`, `counterpart`, `trustedRemote`), chain registry state (`registeredChains`, `gatewayFor`, `chainGateways`),"
    WIKI_EXPLOIT_SCENARIO = "A team deploys a bridge migrator and plans to call `migrateToGateway(realRemoteGateway, multisig)` immediately after deployment. The function is public and only checks that `remoteGateway == address(0)`, `owner == address(0)`, or `gatewayFor[src][dst] == address(0)` before storing route and authority fields. A watcher front-runs with `migrateToGateway(attackerGateway, attacker)` or `registerChain("
    WIKI_RECOMMENDATION = "Do not rely on first-write guards alone. Bind initialization and migration setup to the intended actor with `onlyFactory`, `onlyOwner`, `onlyGovernance`, `onlyBridgeAdmin`, or `require(msg.sender == deployer)` where the deployer is immutably set in the constructor. Better, perform route and authorit"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(initialize|init|setup|bootstrap|register|migrat|gateway|bridge|route|path|peer|counterpart|remote|trustedRemote|endpoint|chain|owner|admin|authority|factory|deployer)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(initialize|init|setup|bootstrap|configure|register|create|add|set|migrate)[A-Z]\\w*(Owner|Admin|Authority|Role|Peer|Counterpart|Remote|TrustedRemote|Endpoint|Gateway|Bridge|Route|Path|Chain|Lane)$|^(setPeer|setCounterpart|setRemoteBridge|setRemoteGateway|setTrustedRemote|setTrustedRemoteAddress|configureRoute|registerRoute|registerPath|registerChain|createChain|addChain|migrateToGateway|migrateChainToGateway|migrateBridgeRoute|initializeGateway)$'}, {'function.source_matches_regex': '(?i)(owner|admin|authority|governor|deployer|factory|peer|counterpart|remoteGateway|remoteBridge|trustedRemote|endpoint|gatewayFor|chainGateways?|registeredChains?|migratedChains?|knownChains?|routeCreated|route|path|chain)'}, {'function.body_contains_regex': '(?i)(require|if)\\s*\\(\\s*[^;{}]*((owner|admin|authority|governor|peer|counterpart|remoteGateway|remoteBridge|trustedRemote|endpoint)\\s*(==|!=)\\s*(address\\s*\\(\\s*0x?0?\\s*\\)|false|true|0)|(routes?|gatewayFor|chainGateways?|registeredChains?|migratedChains?|knownChains?|trustedRemoteLookup|trustedRemotes?|routeCreated)\\s*\\[[^;{}]+\\](\\.length)?\\s*(==|!=)\\s*(address\\s*\\(\\s*0x?0?\\s*\\)|false|true|0)|!\\s*(routeCreated|registeredChains?|migratedChains?|knownChains?)\\s*\\[[^;{}]+\\]|initialized\\s*(==|!=)\\s*(false|true|0))|initializer|reinitializer|AlreadyInitialized'}, {'function.body_contains_regex': '(?i)(owner|admin|authority|governor)\\s*=\\s*(msg\\.sender|_?\\w+)|_grantRole\\s*\\(|_setupRole\\s*\\(|(peer|counterpart|remoteGateway|remoteBridge|trustedRemote|endpoint)\\s*=\\s*_?\\w+|(routes?|gatewayFor|chainGateways?|registeredChains?|migratedChains?|knownChains?|trustedRemoteLookup|trustedRemotes?|routeCreated)\\s*\\[[^;{}]+\\]\\s*='}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|onlyRole|onlyBridgeAdmin|onlyProxy|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))|if\\s*\\(\\s*msg\\.sender\\s*!=\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))\\s*\\)\\s*revert|_checkOwner\\s*\\(|_checkRole\\s*\\(|hasRole\\s*\\(|AccessControl|Ownable|_authorize)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - initialize-or-migrate-first-caller-route-authority-lock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
