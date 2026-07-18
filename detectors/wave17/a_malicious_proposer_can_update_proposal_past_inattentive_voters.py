"""
a-malicious-proposer-can-update-proposal-past-inattentive-voters — generated from reference/patterns.dsl/a-malicious-proposer-can-update-proposal-past-inattentive-voters.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-proposer-can-update-proposal-past-inattentive-voters.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousProposerCanUpdateProposalPastInattentiveVoters(AbstractDetector):
    ARGUMENT = "a-malicious-proposer-can-update-proposal-past-inattentive-voters"
    HELP = "A malicious proposer can update proposal past inattentive voters to sneak in otherwise unacceptable details"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-proposer-can-update-proposal-past-inattentive-voters.yaml"
    WIKI_TITLE = "A malicious proposer can update proposal past inattentive voters to sneak in otherwise unacceptable details"
    WIKI_DESCRIPTION = "## Medium Risk Security Issue\n\n## Context\n- **Affected Files:**\n  - `NounsDAOV3Proposals.sol` (Lines: 269-423)\n  - `NounsDAOV3Admin.sol` (Line: 118)\n  - `NounsDAOV3Votes.sol` (Lines: 70-293)\n\n## Description\nUpdatable proposal description and transactions is a new feature being introduced in V3 to im"
    WIKI_EXPLOIT_SCENARIO = "A malicious proposer can update proposal past inattentive voters to sneak in otherwise unacceptable details"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches_regex': '.*(updateProposal|proposal).*'}, {'function.writes_state_var_matching_regex': '.*(proposal|payload|hash).*'}, {'function.does_not_write_state_var_matching_regex': '.*(notice|invalidate|voter).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-malicious-proposer-can-update-proposal-past-inattentive-voters: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
