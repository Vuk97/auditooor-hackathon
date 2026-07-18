"""
setter-no-zero-address-validation-with-storage-write — generated from reference/patterns.dsl/setter-no-zero-address-validation-with-storage-write.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py setter-no-zero-address-validation-with-storage-write.yaml
Source: solodit-cluster/C0246
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SetterNoZeroAddressValidationWithStorageWrite(AbstractDetector):
    ARGUMENT = "setter-no-zero-address-validation-with-storage-write"
    HELP = "Admin-gated setter (onlyOwner / onlyAdmin / onlyRoles / onlyGovernance) that updates a privileged address slot (owner/admin/treasury/oracle/router/strategy/guardian/implementation/paymaster) without a zero-address check. A single fat-fingered governance transaction writes address(0) into the slot an"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/setter-no-zero-address-validation-with-storage-write.yaml"
    WIKI_TITLE = "Privileged setter missing zero-address validation"
    WIKI_DESCRIPTION = "A function whose name matches the configuration-setter convention (`set*` / `update*` / `change*` / `configure*` suffixed with a privileged-role keyword) accepts an `address` parameter and writes it into storage without first checking `newAddr != address(0)`. The setter is admin-gated, which narrows the caller set to governance actors — but a multisig typo, bad input encoding, or compromised propo"
    WIKI_EXPLOIT_SCENARIO = "Governance proposes `setOracle(newPriceFeed)` but the input calldata is truncated and arrives as `address(0)`. The setter writes `oracle = address(0)` without validation. Every downstream pricing call either reverts (freezing liquidations and withdrawals) or — if the zero slot is treated as a sentinel — silently returns the default zero price, enabling free liquidations of collateral. Recovery req"
    WIKI_RECOMMENDATION = "Add a `require(newAddr != address(0), \"zero address\")` — or a `ZeroAddress()` custom-error revert — at the top of every privileged setter. Centralise via a `_notZero(address)` internal helper or a `notZero` modifier so new setters cannot silently skip the check. For the most critical slots (implem"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'owner|admin|treasury|oracle|router|strategy|guardian|implementation|paymaster'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set|update|change|configure)(Owner|Admin|Treasury|Oracle|Router|Strategy|Guardian|Implementation|Paymaster)'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.has_param_of_type': 'address'}, {'function.writes_storage_matching': '.*'}, {'function.body_not_contains_regex': 'require\\s*\\(.*\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\(.*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)\\s*revert|ZeroAddress\\s*\\(\\s*\\)|_notZero'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — setter-no-zero-address-validation-with-storage-write: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
