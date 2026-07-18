"""
a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting — generated from reference/patterns.dsl/a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AGuardianCannotCancelAMaliciousProposalInAdminvoting(AbstractDetector):
    ARGUMENT = "a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting"
    HELP = "A guardian cannot cancel a malicious proposal in AdminVoting"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting.yaml"
    WIKI_TITLE = "A guardian cannot cancel a malicious proposal in AdminVoting"
    WIKI_DESCRIPTION = "Prisma's AdminVoting intentionally makes a pure guardian-replacement proposal non-cancellable by the guardian. The vulnerable shape applies that carve-out whenever `cancelProposal()` inspects only the first payload action, so a mixed proposal can put `setGuardian()` first and append malicious calls that the guardian can no longer stop."
    WIKI_EXPLOIT_SCENARIO = "An attacker submits a proposal whose first action changes the guardian and whose later actions execute a malicious admin payload. If `cancelProposal()` blocks cancellation based only on the first action being `setGuardian`, the guardian loses the ability to cancel the dangerous multi-action proposal during the execution delay."
    WIKI_RECOMMENDATION = "Only treat guardian replacement as non-cancellable when the payload contains exactly one action. Mixed payloads that merely start with `setGuardian()` must remain cancellable by the guardian."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'proposalPayloads|_isSetGuardianPayload|setGuardian'}, {'contract.not_source_matches_regex': 'payloadLength\\s*==\\s*1\\s*&&\\s*action\\.target\\s*==\\s*address\\s*\\(\\s*prismaCore\\s*\\)'}]
    _MATCH = [{'function.name_matches': '^cancelProposal$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.source_matches_regex': '_isSetGuardianPayload\\s*\\(\\s*(?:payload\\s*\\[\\s*0\\s*\\]|payload\\.length\\s*,\\s*payload\\s*\\[\\s*0\\s*\\])\\s*\\)'}, {'function.source_matches_regex': 'proposalPayloads\\s*\\[\\s*id\\s*\\]|payload\\s*\\[\\s*0\\s*\\]'}]

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
                info = [f, f" — a-guardian-cannot-cancel-a-malicious-proposal-in-adminvoting: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
