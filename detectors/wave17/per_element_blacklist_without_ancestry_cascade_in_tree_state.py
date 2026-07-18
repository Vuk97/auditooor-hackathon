"""
per-element-blacklist-without-ancestry-cascade-in-tree-state — generated from reference/patterns.dsl/per-element-blacklist-without-ancestry-cascade-in-tree-state.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py per-element-blacklist-without-ancestry-cascade-in-tree-state.yaml
Source: auditooor-R111-base-azul-FN-5-narrowed-defense-in-depth
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerElementBlacklistWithoutAncestryCascadeInTreeState(AbstractDetector):
    ARGUMENT = "per-element-blacklist-without-ancestry-cascade-in-tree-state"
    HELP = "Mining prompt only, not submission proof. Defense-in-depth: tree-structured registry / hierarchy with a per-element blacklist mapping but a validity-check view that consults only the queried element's flag, never walking the parent / predecessor chain. Surfaces an ancestry-cascade architectural smel"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/per-element-blacklist-without-ancestry-cascade-in-tree-state.yaml"
    WIKI_TITLE = "Per-element blacklist on a tree without ancestry cascade — defense-in-depth smell"
    WIKI_DESCRIPTION = "Mining prompt only, not submission proof. A registry contract holds a per-element revocation mapping (`mapping(K => bool) blacklisted` / `revoked` / `disabled` / `flagged`) and exposes a validity view (`isClaimValid(K)` / `isAuthorized(K)` / `canFinalize(K)`) that returns false only when the queried element itself is flagged. The contract's data is hierarchical — every element has a `parent()` / `"
    WIKI_EXPLOIT_SCENARIO = "Generic shape (defense-in-depth lens): a hierarchical registry stores `mapping(IElem => bool) blocklist`. When an ancestor element A is added to the blocklist, descendants B and C — already created and finalized off A via `parent()` pointers — are not themselves listed. `isClaimValid(B)` / `isClaimValid(C)` still return true because the function never inspects A. Any downstream consumer that gates"
    WIKI_RECOMMENDATION = "Defense-in-depth fix: make the validity view ancestor-aware so the cascade gap closes regardless of whether other layers also catch the issue.\n\n```solidity\nfunction isClaimValid(IElem g) public view returns (bool) {\n    IElem current = g;\n    while (address(current) != address(0)) {\n        if"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Registry|Tree|Hierarchy|Game|Dispute|Anchor|Subtree|Tournament|Claim|Coverage|Policy|Lineage|Chain)'}, {'contract.source_matches_regex': '(?i)mapping\\s*\\(\\s*\\w+\\s*=>\\s*bool\\s*\\)\\s*(?:public\\s+|internal\\s+|private\\s+)?(?:blacklist|revoked|disabled|removed|flagged|invalidated|nullified)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(isClaimValid|isGameClaimValid|isAuthorized|isAuthorised|isWhitelisted|isOk|canExecute|canFinalize|canClaim|canResolve|isValid|isPermitted|isAllowed|checkValidity|validateClaim)$'}, {'function.body_contains_regex': '(?i)\\b(blacklist|revoked|disabled|removed|flagged|invalidated|nullified)\\w*\\s*\\[\\s*[A-Za-z_][\\w.()]*\\s*\\]'}, {'function.body_not_contains_regex': '\\b(parent|parentOf|predecessor|previousOf|getParent|ancestor|previous|prev|lineage|walkParents|parentAddress|parentGame)\\s*\\('}, {'function.body_not_contains_regex': '\\bwhile\\s*\\(|\\bfor\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — per-element-blacklist-without-ancestry-cascade-in-tree-state: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
