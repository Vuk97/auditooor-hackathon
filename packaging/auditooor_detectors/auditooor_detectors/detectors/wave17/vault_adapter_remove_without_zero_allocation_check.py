"""
vault-adapter-remove-without-zero-allocation-check — generated from reference/patterns.dsl/vault-adapter-remove-without-zero-allocation-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-adapter-remove-without-zero-allocation-check.yaml
Source: auditooor-R101-morpho-V2-BT-M-2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultAdapterRemoveWithoutZeroAllocationCheck(AbstractDetector):
    ARGUMENT = "vault-adapter-remove-without-zero-allocation-check"
    HELP = "Curator/admin removeAdapter() flips `isAdapter[a] = false` without first asserting `allocation[a] == 0`. Vault accounting loops iterate only the live adapter set, so assets still held by the removed adapter become stranded — silently disappear from `totalAssets()` until the adapter is re-added (if e"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-adapter-remove-without-zero-allocation-check.yaml"
    WIKI_TITLE = "Vault `removeAdapter` does not require zero allocation — strands assets and corrupts share price"
    WIKI_DESCRIPTION = "ERC-4626-style vaults that route funds through pluggable adapters track per-adapter allocation in a `caps[id].allocation` (or similar) mapping and iterate the active `adapters[]` array inside `accrueInterest()` / `totalAssets()`. When `removeAdapter(a)` flips `isAdapter[a] = false` without asserting `allocation[a] == 0`, any in-flight allocation becomes invisible: the iteration skips it, share pri"
    WIKI_EXPLOIT_SCENARIO = "Vault has 3 active adapters, each with $10M allocation. Adapter A2 is signalled for removal because the curator wants to swap its underlying strategy. Curator calls `removeAdapter(A2)` (timelocked). Right before removal effective, depositor D1 deposits $30M and is minted shares against `totalAssets() = $30M (3 adapters * $10M)`. Removal fires, `isAdapter[A2] = false`, A2 still holds $10M but it's "
    WIKI_RECOMMENDATION = "At the top of `removeAdapter(adapter)`, assert the allocation has been zeroed first: `require(caps[adapterId].allocation == 0, AdapterStillAllocated());`. Curator must call `decreaseAllocation(adapter, totalAlloc)` (and the de-allocator drains funds back to the vault) BEFORE the removal can succeed."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Vault|Adapter|Strategy|Allocator|Curator'}, {'contract.has_state_var_matching': '(allocation|allocations|caps|adapterCaps|isAdapter|registered|strategies|enabled)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?removeAdapter|_?disableAdapter|_?removeStrategy|_?decommissionAdapter|_?retireAdapter|_?unregisterAdapter|_?deregisterStrategy)$'}, {'function.body_contains_regex': '(isAdapter|registered|enabled|active|isStrategy)\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*false|delete\\s+(adapters|strategies|allocations|caps)\\['}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(allocation|allocations|caps|adapterCaps|balance|shares|totalAssets|realAssets)\\s*[\\[.]|require\\s*\\(\\s*\\w+\\.balanceOf\\s*\\([^)]*\\)\\s*==\\s*0|require\\s*\\(\\s*\\w+\\.realAssets\\s*\\(\\s*\\)\\s*==\\s*0|if\\s*\\(\\s*(allocation|caps|balance)\\s*\\[\\s*\\w+\\s*\\]\\s*!=\\s*0\\s*\\)\\s*revert|caps\\s*\\[[^\\]]+\\]\\s*\\.\\s*allocation\\s*==\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-adapter-remove-without-zero-allocation-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
