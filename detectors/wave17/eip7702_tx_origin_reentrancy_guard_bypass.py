"""
eip7702-tx-origin-reentrancy-guard-bypass — generated from reference/patterns.dsl/eip7702-tx-origin-reentrancy-guard-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip7702-tx-origin-reentrancy-guard-bypass.yaml
Source: auditooor-R73-eip7702-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip7702TxOriginReentrancyGuardBypass(AbstractDetector):
    ARGUMENT = "eip7702-tx-origin-reentrancy-guard-bypass"
    HELP = "`require(tx.origin == msg.sender)` is used as a cheap reentrancy/smart-contract guard, but under EIP-7702 the delegated EOA runs contract code while tx.origin == msg.sender remains true — the guard no longer rules out reentry."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip7702-tx-origin-reentrancy-guard-bypass.yaml"
    WIKI_TITLE = "tx.origin == msg.sender check no longer implies 'no contract at caller address' under EIP-7702"
    WIKI_DESCRIPTION = "Pre-Pectra, `tx.origin == msg.sender` reliably meant the top-level caller was an EOA with no code. With EIP-7702, an EOA delegates to contract code that executes IN THE EOA'S ADDRESS. `tx.origin == msg.sender` therefore still evaluates true even though the caller is executing delegate bytecode capable of reentering, doing arbitrary calls, and holding state. Every protocol using this check as a ree"
    WIKI_EXPLOIT_SCENARIO = "An LP pool has a ‘flash-mint/flash-burn’ convenience entry guarded by `require(tx.origin == msg.sender, 'EOA only')`, trusting that a pure EOA cannot perform multi-hop arbitrage mid-call. Attacker authorizes a 7702 delegate: on entering the guarded function, the delegate's fallback hook runs and calls back into the pool to withdraw pre-update liquidity. tx.origin is still the EOA, so every re-entr"
    WIKI_RECOMMENDATION = "Replace `tx.origin == msg.sender` guards with a real reentrancy guard (OpenZeppelin `nonReentrant`). If the *semantic* goal is 'no-bot-only-human', use a signed eligibility proof instead of an account-type check. Document publicly that the protocol is 7702-aware and does not depend on tx.origin == m"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)tx\\.origin|onlyEOA|noDelegate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'require\\s*\\(\\s*tx\\.origin\\s*==\\s*msg\\.sender\\b|onlyEOA|noContract'}, {'function.body_not_contains_regex': 'nonReentrant|ReentrancyGuard|AUTH_MAGIC|authorizationList'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eip7702-tx-origin-reentrancy-guard-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
