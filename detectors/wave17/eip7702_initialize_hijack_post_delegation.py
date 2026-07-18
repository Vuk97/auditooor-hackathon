"""
eip7702-initialize-hijack-post-delegation — generated from reference/patterns.dsl/eip7702-initialize-hijack-post-delegation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip7702-initialize-hijack-post-delegation.yaml
Source: auditooor-R73-eip7702-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip7702InitializeHijackPostDelegation(AbstractDetector):
    ARGUMENT = "eip7702-initialize-hijack-post-delegation"
    HELP = "A smart-account contract built for 7702 delegation runs `initialize()` in the context of the delegating EOA. If the initialize function isn't locked down, anyone can call it on the EOA's address before the legitimate owner does and claim admin."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip7702-initialize-hijack-post-delegation.yaml"
    WIKI_TITLE = "EIP-7702 smart-account initialize() is race-able in the EOA's storage namespace"
    WIKI_DESCRIPTION = "A contract designed to be a 7702 delegate typically has an `initialize(owner, config)` call that sets up the EOA's storage slots (owner, roles, module registry). When an EOA first authorizes the delegate, the delegate's bytecode executes in the EOA's storage space — but the bytecode's storage is empty for the newly-delegated EOA. If initialize is not tied to a specific caller or to a one-shot cons"
    WIKI_EXPLOIT_SCENARIO = "Alice authorizes 7702 to delegate her EOA to 'SmartWalletV1'. She signs the authorization off-chain and broadcasts. Before her follow-up `initialize(Alice, ...)` tx lands, an MEV bot observes the authorization, front-runs with `SmartWalletV1(Alice).initialize(Attacker, ...)`. The delegate's storage is populated with Attacker as owner. Alice's subsequent init reverts (already initialized). Attacker"
    WIKI_RECOMMENDATION = "Bind initializers to the EIP-7702 authority itself. Either (a) include the expected `owner` as a field in the authorization list and have the delegate read `tx.authorizationList[0].authority` to verify, or (b) run init atomically inside the authorization-tx via a bundler, so nobody can interpose. Do"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)initializer|Initializable|_initialized|initializeV\\d|initialize\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^initiali[sz]e(V\\d+)?$'}, {'function.body_contains_regex': '(?i)(_initialized|reinitializer|initializer\\s*\\{)'}, {'function.body_not_contains_regex': '(?i)(onlyProxy|\\.delegatecall|_disableInitializers|AUTH_MAGIC|7702)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eip7702-initialize-hijack-post-delegation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
