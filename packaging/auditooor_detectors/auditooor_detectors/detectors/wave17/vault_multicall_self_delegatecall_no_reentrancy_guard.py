"""
vault-multicall-self-delegatecall-no-reentrancy-guard — generated from reference/patterns.dsl/vault-multicall-self-delegatecall-no-reentrancy-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-multicall-self-delegatecall-no-reentrancy-guard.yaml
Source: auditooor-R110-morpho-VaultV2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultMulticallSelfDelegatecallNoReentrancyGuard(AbstractDetector):
    ARGUMENT = "vault-multicall-self-delegatecall-no-reentrancy-guard"
    HELP = "A `multicall(bytes[])` helper iterates over user-supplied calldata and dispatches each entry via `address(this).delegatecall(data[i])` with no `nonReentrant` modifier. Any function reachable through one of those selectors that fires an external call (token transfer, adapter hook, gate callback, ERC-"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-multicall-self-delegatecall-no-reentrancy-guard.yaml"
    WIKI_TITLE = "`multicall` self-`delegatecall` loop without reentrancy guard"
    WIKI_DESCRIPTION = "EOA-batch-friendly vaults expose a `multicall(bytes[] calldata data)` helper that iterates user-supplied calldata and runs each entry against the contract's own storage via `address(this).delegatecall(data[i])`. The pattern is borrowed from OpenZeppelin's `MulticallUpgradeable`, but most reference implementations include a `nonReentrant` modifier (or assume the caller holds the only mutex). When t"
    WIKI_EXPLOIT_SCENARIO = "VaultV2 has `multicall` (line 280) and `forceDeallocate` (line 749). User crafts a multicall payload `[deposit(X, attacker), forceDeallocate(adapter, data, X', attacker)]`. The first `delegatecall(deposit)` increments `_totalAssets` by X, mints attacker shares, and (because `liquidityAdapter != 0`) calls `allocateInternal` which fires `IAdapter(liquidityAdapter).allocate(...)`. The adapter is a ho"
    WIKI_RECOMMENDATION = "Add `nonReentrant` (OZ `ReentrancyGuard` modifier) to the `multicall` function. The OZ implementation tracks a `_status` slot and reverts on re-entrant entry. Alternatively, use a transient-storage flag (`bytes32 transient _multicallEntered;`) — set on entry, reset on exit, revert if already set. Th"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Vault|Strategy|Adapter|Bundler|Multicall|Router|Aggregator|Wrapper|Manager'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?multicall|_?batch|_?execBatch|_?multiExec|_?batchExec|_?aggregate|_?multiAction)$'}, {'function.body_contains_regex': 'address\\s*\\(\\s*this\\s*\\)\\s*\\.\\s*delegatecall\\s*\\(|self\\s*\\.\\s*delegatecall\\s*\\(|\\bthis\\s*\\.\\s*delegatecall\\s*\\('}, {'function.body_not_contains_regex': '\\bnonReentrant\\b|ReentrancyGuard|_reentrancyLock|_locked\\s*=|_status\\s*=\\s*_ENTERED|reentrancyGuard_|noReenter'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-multicall-self-delegatecall-no-reentrancy-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
