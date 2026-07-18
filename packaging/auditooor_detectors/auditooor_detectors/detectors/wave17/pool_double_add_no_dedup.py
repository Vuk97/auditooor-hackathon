"""
pool-double-add-no-dedup — generated from reference/patterns.dsl/pool-double-add-no-dedup.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pool-double-add-no-dedup.yaml
Source: solodit-cluster/C0223
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PoolDoubleAddNoDedup(AbstractDetector):
    ARGUMENT = "pool-double-add-no-dedup"
    HELP = "Pool registry add*Pool appends without duplicate check; same pool can be registered twice, double-counting rewards."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pool-double-add-no-dedup.yaml"
    WIKI_TITLE = "Pool registry missing duplicate-add check"
    WIKI_DESCRIPTION = "An add*Pool / registerPool / createPool entrypoint pushes a pool address or struct into the contract's pool registry without first verifying the pool isn't already present. Duplicates inflate reward accounting in MasterChef-style loops, break enumeration-based logic, and can be used to grief gas limits or double-count TVL."
    WIKI_EXPLOIT_SCENARIO = "The admin (or an unrestricted entrypoint) calls addPool with a pool address that was already added in an earlier transaction. The pool now appears twice in the `pools` array. On the next massUpdatePools / distribute() pass, reward shares for that pool are allocated twice, letting depositors in the duplicated pool withdraw rewards that should have been spread across all real pools. In the worst cas"
    WIKI_RECOMMENDATION = "Before appending, require that the pool is not already registered. Typical fixes: (1) maintain a `mapping(address => bool) isPool` and `require(!isPool[newPool])` at the start of addPool; (2) use OpenZeppelin `EnumerableSet.AddressSet` and rely on `.add()` returning false on duplicate; (3) track `ma"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pools|poolList|poolInfo|registeredPools'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(addPool|addNewPool|addLPPool|addRewardPool|addStakingPool|registerPool|registerNewPool|createPool|createNewPool|addCurated|addCuratedPool|addStrategy|addStrategyPool|addVault|addVaultPool)$'}, {'function.body_contains_regex': {'regex': '\\.push\\s*\\(|pools\\.length|pools\\[.*\\]\\s*=|\\.add\\s*\\('}}, {'function.body_not_contains_regex': 'require\\s*\\(.*(!isPool|!registered|!contains|==\\s*address\\(0\\)|==\\s*0).*\\)|isActive|alreadyAdded|isRegistered|EnumerableSet.*contains'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pool-double-add-no-dedup: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
