"""
blacklist-bypass-transferfrom — generated from reference/patterns.dsl/blacklist-bypass-transferfrom.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py blacklist-bypass-transferfrom.yaml
Source: solodit-cluster-C0146
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BlacklistBypassTransferfrom(AbstractDetector):
    ARGUMENT = "blacklist-bypass-transferfrom"
    HELP = "transferFrom / burn path on a blacklist-bearing token omits the blacklist check that transfer enforces, letting approved addresses move or destroy a blacklisted user's balance."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/blacklist-bypass-transferfrom.yaml"
    WIKI_TITLE = "Blacklist bypass via transferFrom / burn"
    WIKI_DESCRIPTION = "The contract maintains a blacklist / frozen / denyList state variable and enforces it on the `transfer` path, but the `transferFrom`, `_transferFrom`, `burn`, `_burn`, or `burnFrom` path never consults the same list. A blacklisted holder can still have their tokens moved or burned by a previously-approved operator, and in some deployments can self-bypass by approving a fresh address and pulling fr"
    WIKI_EXPLOIT_SCENARIO = "Sanctions or compliance tooling blacklists address B. B had previously approved operator O for unlimited allowance. Because transferFrom omits the blacklist check, O calls transferFrom(B, C, balanceOf(B)) and drains B's position. Alternatively, if the burn path is unguarded, a hostile minter can burn a blacklisted user's balance without their consent."
    WIKI_RECOMMENDATION = "Apply the same blacklist / denyList / frozen guard on every value-moving path — transfer, transferFrom, burn, burnFrom, and any custom move/sweep function — ideally via a shared `notBlacklisted(from)` modifier or a single internal `_beforeTokenTransfer` hook that every path funnels through."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'blacklist|blocked|frozen|denyList|banned'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(transferFrom|_transferFrom|burn|_burn|burnFrom)$'}, {'function.body_not_contains_regex': 'blacklist\\s*\\[|_blacklist\\s*\\[|blocked\\s*\\[|_blocked\\s*\\[|frozen\\s*\\[|_frozen\\s*\\[|denyList\\s*\\[|_denyList\\s*\\[|banned\\s*\\[|_banned\\s*\\[|isBlacklisted\\s*\\(|isBlocked\\s*\\(|isFrozen\\s*\\(|isDenied\\s*\\(|isBanned\\s*\\(|require\\s*\\(\\s*!\\s*\\w*(blacklist|blocked|frozen|denyList|banned)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — blacklist-bypass-transferfrom: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
