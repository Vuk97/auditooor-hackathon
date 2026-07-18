"""
upgradeable-proxy-implementation-history-writes-attacker-balance — generated from reference/patterns.dsl/upgradeable-proxy-implementation-history-writes-attacker-balance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py upgradeable-proxy-implementation-history-writes-attacker-balance.yaml
Source: auditooor-R76-rekt-munchables-2024
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UpgradeableProxyImplementationHistoryWritesAttackerBalance(AbstractDetector):
    ARGUMENT = "upgradeable-proxy-implementation-history-writes-attacker-balance"
    HELP = "Proxy upgrade entrypoint accepts any new implementation. A malicious impl can write arbitrary storage (user balances, roles) before being replaced by a benign impl whose logic doesn't reconcile that injected state."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/upgradeable-proxy-implementation-history-writes-attacker-balance.yaml"
    WIKI_TITLE = "Upgradeable proxy has no implementation-bytecode allowlist, enabling storage-injection via hostile intermediate impl"
    WIKI_DESCRIPTION = "An upgradeable proxy whose `_authorizeUpgrade` only checks `onlyOwner` (but allows ANY bytecode as the new implementation) is vulnerable to a two-step attack: (1) owner upgrades to a hostile impl that writes attacker-chosen entries into storage slots (user balance mapping, admin roles, critical constants); (2) owner upgrades back to the 'legitimate' impl whose runtime checks trust the now-corrupte"
    WIKI_EXPLOIT_SCENARIO = "Insider-dev with UPGRADER_ROLE calls `proxy.upgradeToAndCall(hostileImpl, initCalldata)`. hostileImpl's fallback writes `_balances[attacker] = 1_000_000 ether`. Dev then calls `proxy.upgradeTo(cleanImpl)` where cleanImpl is the 'real' contract with proper deposit/withdraw logic. Users deposit ETH; the proxy's total balance grows. Attacker calls `withdraw(1_000_000 ether)`; cleanImpl sees `_balance"
    WIKI_RECOMMENDATION = "Maintain an on-chain allowlist of implementation bytecode hashes: `require(implRegistry.isAllowed(keccak256(newImplementation.code)), 'impl not allowlisted');`. For additional defense, enforce a storage-layout-unchanged invariant via a deterministic post-upgrade `checkStorageIntegrity()` call that v"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Contract is a UUPS / transparent proxy with upgradeTo() callable by a role/EOA, and no on-chain restriction on which implementation contract can be installed.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)upgradeTo|upgradeToAndCall|_authorizeUpgrade|setImplementation'}, {'function.body_contains_regex': '(?i)_upgradeTo|StorageSlot|_IMPLEMENTATION_SLOT|ERC1967|newImplementation'}, {'function.body_not_contains_regex': '(?i)isVerifiedImpl|whitelistedImpl|implementationAllowlist|blockhashOfImpl|extcodehash\\s*\\(\\s*\\w*[iI]mpl\\w*\\s*\\)\\s*==|require\\s*\\(\\s*ImplRegistry'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — upgradeable-proxy-implementation-history-writes-attacker-balance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
