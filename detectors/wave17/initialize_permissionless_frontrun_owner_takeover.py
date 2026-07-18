"""
initialize-permissionless-frontrun-owner-takeover — generated from reference/patterns.dsl/initialize-permissionless-frontrun-owner-takeover.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py initialize-permissionless-frontrun-owner-takeover.yaml
Source: auditooor-R75-c4-mined-2023-12-autonolas-418
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitializePermissionlessFrontrunOwnerTakeover(AbstractDetector):
    ARGUMENT = "initialize-permissionless-frontrun-owner-takeover"
    HELP = "`initialize()` sets `owner = msg.sender` and only guards against re-initialization via `require(owner == address(0))`. It has no access control. If the contract is deployed separately from its initialization tx (typical for upgrade/proxy flows or factory-deployed implementations), anyone in the memp"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/initialize-permissionless-frontrun-owner-takeover.yaml"
    WIKI_TITLE = "Permissionless initialize() is front-runnable, attacker becomes contract owner"
    WIKI_DESCRIPTION = "`initializeTokenomics(...)` is external and only checks `if (owner != address(0)) revert AlreadyInitialized();` before `owner = msg.sender`. No onlyDeployer/onlyOwner modifier, not using OpenZeppelin's `initializer` modifier paired with `_disableInitializers()` in the constructor. Any observer who sees the deployment tx submits their own initialize in the next block with valid-looking parameters ("
    WIKI_EXPLOIT_SCENARIO = "Autonolas deploys Tokenomics at address T. Deployer's nonce+1 tx is `initializeTokenomics(olas, treasury, depo, dispenser, ve, epochLen=7d, …)`. Attacker front-runs with the same parameters except providing attacker-controlled registry addresses (which still pass the nonzero check). Attacker is now `owner`. Attacker immediately calls `changeTokenomicsImplementation(maliciousImpl)` (it's a proxy). "
    WIKI_RECOMMENDATION = "Use OpenZeppelin Upgrades `initializer` modifier AND call `_disableInitializers()` in the implementation's constructor. For non-upgradeable contracts with init, gate `initialize` with `require(msg.sender == deployer)` where `deployer` is set immutably in the constructor. Invariant: deploying and att"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Tokenomics|Treasury|Dispenser|Initializable|initializeTokenomics|initialize'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(initialize|initializeTokenomics|init|__init)$'}, {'function.body_contains_regex': 'owner\\s*=\\s*msg\\.sender|_owner\\s*=\\s*msg\\.sender|_transferOwnership\\s*\\(\\s*msg\\.sender\\s*\\)'}, {'function.body_contains_regex': 'if\\s*\\(\\s*owner\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)\\s*revert|require\\s*\\(\\s*owner\\s*==\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.body_not_contains_regex': '(onlyOwner|onlyAdmin|onlyDeployer|require\\s*\\(\\s*msg\\.sender\\s*==\\s*deployer|initializer\\s+modifier|Initializable|_disableInitializers)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — initialize-permissionless-frontrun-owner-takeover: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
