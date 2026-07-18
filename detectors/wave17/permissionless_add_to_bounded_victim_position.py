"""
permissionless-add-to-bounded-victim-position — generated from reference/patterns.dsl/permissionless-add-to-bounded-victim-position.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permissionless-add-to-bounded-victim-position.yaml
Source: auditooor-R107-thegraph-OZ-M-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PermissionlessAddToBoundedVictimPosition(AbstractDetector):
    ARGUMENT = "permissionless-add-to-bounded-victim-position"
    HELP = "A permissionless function lets any caller add tokens / a record into another user's per-account slot, where downstream checks enforce a TIGHT validity range (`min <= total <= max`, or per-list cap). A malicious caller pushes a 1-wei amount (or a single record) into the victim's slot, breaking the va"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permissionless-add-to-bounded-victim-position.yaml"
    WIKI_TITLE = "Permissionless `addToX(victim, ...)` enables tight-bound griefing of victim's operations"
    WIKI_DESCRIPTION = "When a contract enforces both a lower and an upper bound on a per-account slot — e.g. a data service that requires `minProvision <= prov.tokens <= maxProvision`, a vault with per-account caps, an NFT collection with per-wallet limits — any function that lets an arbitrary caller increment the victim's slot becomes a griefing primitive. Even a 1-wei push is enough to put the victim out of range, and"
    WIKI_EXPLOIT_SCENARIO = "An ETH-staking-style data service requires each indexer's provision to satisfy `prov.tokens == 32 ether` exactly (validator slot semantics: equality, not range). The staking contract exposes `stakeToProvision(provider, verifier, tokens)` with no auth check — anyone can call it with `tokens = 1`. After the call, `prov.tokens = 32 ether + 1`, which violates the equality. The data service's `collect("
    WIKI_RECOMMENDATION = "Gate the function with an authorization check that scopes who can credit a given victim — e.g. `onlyAuthorized(serviceProvider)`, `onlyOperator(target)`, or `require(msg.sender == target)` for full self-only semantics. If permissionless deposits are intentional (e.g. donation flows), the validity ch"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(add|push|stake|deposit|register|delegate|provision|fund|mint|vest|cover)(For|To|On|OnBehalf|Behalf|Pool|Provision|Vault|Allocation|Position)\\w*$'}, {'function.has_param_name_matching': '(?i)^(_?serviceProvider|_?recipient|_?beneficiary|_?victim|_?target|_?account|_?owner|_?user|_?delegatee|_?delegator|to|_?forAddress|_?forUser|_?onBehalfOf)$'}, {'function.body_not_contains_regex': '(?i)\\b(onlyAuthorized|onlyAuthorizedOrVerifier|onlyOperator|onlyOwner|onlyAdmin|onlyRole\\s*\\(|require\\s*\\([^)]*msg\\.sender\\s*==\\s*(?:_?\\w+\\s*\\)|address\\s*\\())'}, {'function.body_contains_regex': '\\b\\w+\\s*\\[\\s*\\w+\\s*\\][^=]*\\.\\w+\\s*(?:\\+=|=\\s*\\w+(?:\\.\\w+)?\\s*\\+\\s*)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permissionless-add-to-bounded-victim-position: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
