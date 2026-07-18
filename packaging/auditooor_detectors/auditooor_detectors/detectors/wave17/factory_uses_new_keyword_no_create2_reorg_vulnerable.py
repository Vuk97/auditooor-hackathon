"""
factory-uses-new-keyword-no-create2-reorg-vulnerable — generated from reference/patterns.dsl/factory-uses-new-keyword-no-create2-reorg-vulnerable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py factory-uses-new-keyword-no-create2-reorg-vulnerable.yaml
Source: lisa-mine-r99-case-05980-c4-pooltogether-2023-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FactoryUsesNewKeywordNoCreate2ReorgVulnerable(AbstractDetector):
    ARGUMENT = "factory-uses-new-keyword-no-create2-reorg-vulnerable"
    HELP = "Factory `createX()` deploys a child contract via the `new` keyword (CREATE opcode). The deployed address depends only on `(factory_address, factory_nonce)` — both observable on-chain, so any chain reorg that re-orders the factory's transaction history produces a different address, and any user who s"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/factory-uses-new-keyword-no-create2-reorg-vulnerable.yaml"
    WIKI_TITLE = "Factory uses `new` (CREATE) — reorg-vulnerable address derivation"
    WIKI_DESCRIPTION = "Pattern fires on factory entry points named `createXxx` / `deployXxx` / `spawnXxx` whose body contains `new ChildType(...)` (the CREATE opcode form) without any `salt:` modifier and without an explicit `Create2`/`CREATE2` deployment helper. CREATE addresses derive from the factory's nonce; on chains susceptible to reorgs (Polygon, Arbitrum, ZKSync, BSC) or in cross-chain deployment workflows, an o"
    WIKI_EXPLOIT_SCENARIO = "User pre-computes the address of `VaultBooster #N` via `factory_addr, factory_nonce` and seeds the child with a yield deposit before calling `createVaultBooster`. A reorg pushes the factory's transaction history one position later — the same factory call now creates a different child contract address, and the user's deposit is held by an unrelated CREATE-derived address. Anyone who calls `createVa"
    WIKI_RECOMMENDATION = "Use CREATE2 with a caller-supplied salt: `new ChildType{salt: keccak256(abi.encode(msg.sender, params))}(...)`. Document the resulting address derivation. Where deterministic addresses are required across chains, use the OpenZeppelin `Create2` helper or a CREATE3 factory so deployment hashes — not f"

    _PRECONDITIONS = [{'contract.has_function_matching': 'create|deploy|build|spawn'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'create[A-Z]|deploy[A-Z]|spawn[A-Z]|build[A-Z]'}, {'function.body_contains_regex': '\\bnew\\s+[A-Z][A-Za-z0-9_]*\\s*\\('}, {'function.body_not_contains_regex': '\\bnew\\s+[A-Z][A-Za-z0-9_]*\\s*\\{[^}]*salt\\s*:|\\bcreate2\\s*\\(|Create2\\.deploy|CREATE2|computeAddress\\s*\\(\\s*salt'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — factory-uses-new-keyword-no-create2-reorg-vulnerable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
