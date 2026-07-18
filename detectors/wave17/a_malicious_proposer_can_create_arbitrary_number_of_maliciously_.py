"""
a-malicious-proposer-can-create-arbitrary-number-of-maliciously- — generated from reference/patterns.dsl/a-malicious-proposer-can-create-arbitrary-number-of-maliciously-.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-proposer-can-create-arbitrary-number-of-maliciously-.yaml
Source: Spearbit/Nouns DAO (Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousProposerCanCreateArbitraryNumberOfMaliciously(AbstractDetector):
    ARGUMENT = "a-malicious-proposer-can-create-arbitrary-number-of-maliciously-"
    HELP = "A malicious proposer can create arbitrary number of maliciously updatable proposals to significantly grief the protocol"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-proposer-can-create-arbitrary-number-of-maliciously-.yaml"
    WIKI_TITLE = "A malicious proposer can create arbitrary number of maliciously updatable proposals to significantly grief the protocol"
    WIKI_DESCRIPTION = "## Severity: Medium Risk\n\n## Context\n- `NounsDAOV3Proposals.sol#L783-L798`\n- `NounsDAOV3Proposals.sol#L171`\n- `NounsDAOV3Proposals.sol#L818-L823`\n- `NounsDAOV3Proposals.sol#L269-L423`\n\n## Description\n`checkNoActiveProp()` is documented as: \n> \"This is a spam protection mechanism to limit the number"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #21324: ## Severity: Medium Risk\n\n## Context\n- `NounsDAOV3Proposals.sol#L783-L798`\n- `NounsDAOV3Proposals.sol#L171`\n- `NounsDAOV3Proposals.sol#L818-L823`\n- `NounsDAOV3Proposals.sol#L269-L423`\n\n## Description"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(updateProposal|updatable|updateable)'}]
    _MATCH = [{'function.name_matches_regex': '^(checkNoActiveProp)$'}, {'function.reads_state_var_matching_regex': '(?i)(latestProposal|proposalState|proposals)'}, {'function.body_contains_regex': '(?i)\\b(Pending|Active)\\b'}, {'function.body_not_contains_regex': '(?i)\\b(Updatable|Updateable)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-malicious-proposer-can-create-arbitrary-number-of-maliciously-: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
