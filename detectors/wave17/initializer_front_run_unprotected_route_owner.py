"""
initializer-front-run-unprotected-route-owner

Hand-written detector for setup entrypoints that write owner/admin or route
state while lacking both caller authorization and initializer protection.
Source: reports/realworld_recall_drilldown_initializer-front-run.json
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitializerFrontRunUnprotectedRouteOwner(AbstractDetector):
    ARGUMENT = "initializer-front-run-unprotected-route-owner"
    HELP = (
        "Public setup or initializer-like route/owner binding writes owner, "
        "admin, gateway, peer, or route state without caller authorization or "
        "initializer protection."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/"
        "reports/detector_lift_wave_20260604/worker_ff_initializer_front_run_solidity.md"
    )
    WIKI_TITLE = "Initializer or route setup lacks caller binding"
    WIKI_DESCRIPTION = (
        "A deployment or migration setup function is externally reachable and "
        "writes long-lived authority or route state before the intended binder "
        "is established. Without an owner, admin, factory, deployer, or "
        "initializer guard, any address can front-run the setup transaction and "
        "store attacker-controlled owner/admin or bridge route state."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A bridge registry is deployed and the team plans to call setupRoute in "
        "the next transaction. A watcher calls setupRoute first with an attacker "
        "admin and remote gateway. The contract stores those values and later "
        "routing or administration resolves to attacker-controlled state."
    )
    WIKI_RECOMMENDATION = (
        "Bind setup to the intended actor with onlyOwner, onlyAdmin, "
        "onlyFactory, onlyRole, or require(msg.sender == deployer). For "
        "upgradeable deployments, use initializer or reinitializer semantics and "
        "initialize atomically with deployment when possible."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                "(?i)(initialize|init|setup|bootstrap|configure|register|"
                "migrat|route|gateway|bridge|peer|remote|chain|owner|admin|"
                "authority|factory|deployer|binder)"
            )
        }
    ]

    _AUTH_OR_INIT_GUARD_RE = (
        "(?is)("
        "onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
        "onlyDeployer|onlyRole|onlyBridgeAdmin|onlyProxy|requiresAuth|"
        "requireAuth|auth\\s*\\(|restricted|initializer|reinitializer|"
        "onlyInitializing|"
        "require\\s*\\([^;]{0,220}(msg\\.sender|_msgSender\\s*\\(\\s*\\))"
        ".{0,140}(owner|_owner|admin|_admin|governance|governor|deployer|"
        "factory|bridgeAdmin|binder)|"
        "require\\s*\\([^;]{0,220}(owner|_owner|admin|_admin|governance|"
        "governor|deployer|factory|bridgeAdmin|binder).{0,140}"
        "(msg\\.sender|_msgSender\\s*\\(\\s*\\))|"
        "if\\s*\\([^;]{0,220}(msg\\.sender|_msgSender\\s*\\(\\s*\\))"
        ".{0,140}(owner|admin|governance|governor|deployer|factory|"
        "bridgeAdmin|binder).{0,120}revert|"
        "_checkOwner\\s*\\(|_checkRole\\s*\\(|hasRole\\s*\\(|"
        "AccessControl|OwnableUnauthorizedAccount|"
        "require\\s*\\(\\s*!\\s*initialized\\b|"
        "require\\s*\\(\\s*initialized\\s*==\\s*false|"
        "if\\s*\\(\\s*initialized\\s*\\)\\s*revert|"
        "if\\s*\\(\\s*initialized\\s*==\\s*true\\s*\\)\\s*revert"
        ")"
    )

    _MATCH = [
        {"function.kind": "external_or_public"},
        {"function.is_mutating": True},
        {
            "function.name_matches": (
                "(?i)^(initialize|init|setup|bootstrap|configure|register|"
                "create|add|set|migrate)\\w*"
            )
        },
        {
            "function.source_matches_regex": (
                "(?i)(owner|admin|authority|governor|binder|peer|remote|"
                "gateway|bridge|route|chain|registry|config)"
            )
        },
        {
            "function.writes_state_var_matching_regex": (
                "(?i)(owner|admin|authority|governor|binder|peer|remote|"
                "gateway|bridge|route|routes|chain|registry|config|factory|"
                "deployer|initialized)"
            )
        },
        {
            "function.body_contains_regex": (
                "(?is)("
                "(owner|admin|authority|governor|binder)\\s*=\\s*"
                "(msg\\.sender|_?\\w+)|"
                "(peer|remote\\w*|gateway\\w*|bridge\\w*)\\s*=\\s*_?\\w+|"
                "(routes?|routeOwner|routeAdmin|gatewayFor|chainGateways?|"
                "registeredChains?|trustedRemoteLookup|trustedRemotes?|"
                "routeCreated|config\\w*)\\s*\\[[^;{}]+\\]\\s*=|"
                "_grantRole\\s*\\(|_setupRole\\s*\\("
                ")"
            )
        },
        {"function.not_modifiers_match": _AUTH_OR_INIT_GUARD_RE},
        {"function.body_not_contains_regex": _AUTH_OR_INIT_GUARD_RE},
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {"function.not_source_matches_regex": "(?i)\\b(mock|test|fixture|example|demo)\\b"},
    ]

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
                info = [
                    f,
                    (
                        " - initializer-front-run-unprotected-route-owner: "
                        "setup path writes authority or route state without "
                        "authorization or initializer guard."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
