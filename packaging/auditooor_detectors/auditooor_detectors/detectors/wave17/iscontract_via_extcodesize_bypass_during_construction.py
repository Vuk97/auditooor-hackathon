"""
iscontract-via-extcodesize-bypass-during-construction — generated from reference/patterns.dsl/iscontract-via-extcodesize-bypass-during-construction.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py iscontract-via-extcodesize-bypass-during-construction.yaml
Source: lisa-mine-r99-case-08190-spearbit-angle-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IscontractViaExtcodesizeBypassDuringConstruction(AbstractDetector):
    ARGUMENT = "iscontract-via-extcodesize-bypass-during-construction"
    HELP = "`_isContract` helper checks `extcodesize(addr) > 0` to gate a 'contracts only' guard (e.g. blocklist of bot contracts, anti-flash-loan guard). The check returns FALSE for an address mid-construction (in its own `constructor` body), and FALSE for a CREATE2-derived address that hasn't been deployed ye"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/iscontract-via-extcodesize-bypass-during-construction.yaml"
    WIKI_TITLE = "isContract via extcodesize bypassed during construction / post-selfdestruct"
    WIKI_DESCRIPTION = "Pattern fires on `_isContract` / `isContract` helpers whose only check is `extcodesize(addr) > 0`. Three known ways to bypass: (1) call from a contract's constructor — codesize is 0 until deployment finishes; (2) CREATE2 deploy → action → selfdestruct → re-deploy in the same transaction — the address has codesize 0 between deploy/selfdestruct; (3) `tx.origin` proxying — a contract calls through an"
    WIKI_EXPLOIT_SCENARIO = "Angle's Blocklist contract uses `_isContract(msg.sender)` to enforce 'only contracts can be blocklisted'. An attacker deploys a contract via CREATE2, has it acquire VE governance power, then `selfdestruct`s — the empty address still holds the governance receipts. Manager calls `block(emptyAddress)` — `_isContract` returns false (codesize == 0), the call reverts with 'Only contracts'. The attacker "
    WIKI_RECOMMENDATION = "Combine `extcodesize` with `tx.origin == msg.sender` (rejects construction-frame and proxy bypasses) — but acknowledge `tx.origin` introduces its own auth foot-gun. Better: maintain an admin-curated allow-list / block-list of canonical contract addresses, and let on-chain enforcement key off members"

    _PRECONDITIONS = [{'contract.has_function_matching': '_isContract|isContract|onlyContracts|requireContract|block'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(_isContract|isContract|_onlyContract)$'}, {'function.body_contains_regex': 'extcodesize\\s*\\(\\s*[A-Za-z_]\\w*\\s*\\)|\\bcode\\.length\\s*>'}, {'function.body_not_contains_regex': '\\.code\\.length\\s*==\\s*0\\s*&&\\s*tx\\.origin|preventBypass|isCalledFromConstructor|require.*msg\\.sender\\s*!=\\s*tx\\.origin|address\\s+sender\\s*=\\s*tx\\.origin'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — iscontract-via-extcodesize-bypass-during-construction: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
