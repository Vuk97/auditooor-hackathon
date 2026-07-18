"""
public-route-or-chain-migration-first-writer - generated from reference/patterns.dsl/public-route-or-chain-migration-first-writer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py public-route-or-chain-migration-first-writer.yaml
Source: auditooor.vault_realworld_recall_gap_priorities.v1:d414c23168765b8a initializer-front-run recall lift
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PublicRouteOrChainMigrationFirstWriter(AbstractDetector):
    ARGUMENT = "public-route-or-chain-migration-first-writer"
    HELP = "Public first-writer chain or route migration stores bridge gateway state without caller binding and without rejecting identical or invalid chain ids."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/public-route-or-chain-migration-first-writer.yaml"
    WIKI_TITLE = "Public route or chain migration first writer controls gateway state"
    WIKI_DESCRIPTION = "Bridge deployments often create a chain, route, or gateway lane in a post-deploy migration transaction. The risky shape is a public `register*`, `configure*`, or `migrate*` entrypoint that writes the route registry only if the slot is empty, but does not bind that first write to the factory, deployer, governance, or an admin role. If the same function also accepts `sourceChainId` and `destinationChainId` without rejecting equal or zero values, the first writer can claim a real route, create a degenerate self-route, or wedge a newly migrated chain into the wrong gateway namespace."
    WIKI_EXPLOIT_SCENARIO = "A bridge team deploys a new gateway and plans to call `migrateChainToGateway(10, 42161, realGateway)`. The function is public and only checks that `gatewayFor[10][42161] == address(0)` and that the route key has not been created. A watcher front-runs with `migrateChainToGateway(10, 10, attackerGateway)` or with the intended pair and an attacker gateway. The first write marks the route as created, downstream lookups resolve to the attacker-selected or degenerate route, and the legitimate migration reverts because the namespace is no longer empty."
    WIKI_RECOMMENDATION = "Bind first-writer route setup to the intended actor with `onlyFactory`, `onlyGovernance`, `onlyRole`, or an immutable deployer check. Reject `sourceChainId == destinationChainId`, zero chain ids, unsupported chain ids, and zero gateways before writing route state. Prefer atomic factory deployment plus initialization when possible so the route namespace cannot be claimed in a separate transaction."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|route|chain|migration|migrate|registry)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(setup|configure|register|create|add|migrate|initialize)[A-Z]\\w*(Route|Path|Chain|Gateway|Bridge|Migration)|^(registerRoute|registerChain|createChain|addChain|configureRoute|setupRoute|migrateChainToGateway|migrateToGateway)$'}, {'function.source_matches_regex': '(?i)\\b(source|src|origin|from)\\w*Chain(Id)?\\b'}, {'function.source_matches_regex': '(?i)\\b(destination|dest|dst|remote|target|to)\\w*Chain(Id)?\\b'}, {'function.body_contains_regex': '(?i)(require|if)\\s*\\([^;{}]*((routes?|gatewayFor|chainGateways?|registeredChains?|migratedChains?|routeCreated|knownChains?)\\s*\\[[^;{}]+\\]\\s*(==|!=)\\s*(address\\s*\\(\\s*0x?0?\\s*\\)|false|true|0)|!\\s*(routeCreated|registeredChains?|migratedChains?|knownChains?)\\s*\\[[^;{}]+\\])'}, {'function.body_contains_regex': '(?i)(routes?|gatewayFor|chainGateways?|registeredChains?|migratedChains?|routeCreated|knownChains?)\\s*\\[[^;{}]+\\]\\s*='}, {'function.body_contains_regex': '(?i)(gateway|router|bridge|peer|route|path)'}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|onlyDeployer|onlyRole|onlyBridgeAdmin|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))|if\\s*\\(\\s*msg\\.sender\\s*!=\\s*(_?(owner|admin|governance|governor|deployer|factory|bridgeAdmin)|owner\\(\\)|admin\\(\\)|governance\\(\\))\\s*\\)\\s*revert|_checkOwner\\s*\\(|_checkRole\\s*\\(|hasRole\\s*\\(|AccessControl|Ownable)'}, {'function.body_not_contains_regex': '(?i)(SameChain|InvalidSameChain|sourceChainId\\s*==\\s*destinationChainId|destinationChainId\\s*==\\s*sourceChainId|_sourceChainId\\s*==\\s*_destinationChainId|_destinationChainId\\s*==\\s*_sourceChainId)'}, {'function.body_not_contains_regex': '(?i)(InvalidChain|ZeroChain|UnsupportedChain|validChain|isChainSupported|sourceChainId\\s*==\\s*0|destinationChainId\\s*==\\s*0|_sourceChainId\\s*==\\s*0|_destinationChainId\\s*==\\s*0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|example)\\b'}]

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
                info = [f, f" - public-route-or-chain-migration-first-writer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
