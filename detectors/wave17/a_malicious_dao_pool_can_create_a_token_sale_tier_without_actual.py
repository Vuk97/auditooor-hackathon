"""
a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual — generated from reference/patterns.dsl/a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousDaoPoolCanCreateATokenSaleTierWithoutActual(AbstractDetector):
    ARGUMENT = "a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual"
    HELP = "A malicious DAO Pool can create a token sale tier without actually transferring any DAO tokens"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual.yaml"
    WIKI_TITLE = "A malicious DAO Pool can create a token sale tier without actually transferring any DAO tokens"
    WIKI_DESCRIPTION = "**Description:** `TokenSaleProposalCreate::createTier` is called by a DAO Pool owner to create a new token sale tier. A fundamental prerequisite for creating a tier is that the DAO Pool owner must transfer the `totalTokenProvided` amount of DAO tokens to the `TokenSaleProposal`.\n\nCurrent implementat"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #27298: **Description:** `TokenSaleProposalCreate::createTier` is called by a DAO Pool owner to create a new token sale tier. A fundamental prerequisite for creating a tier is that the DAO Pool owner must tra"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(createTier|totalTokenProvided|TokenSaleProposal)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^createTier$|_createTier$'}, {'function.has_param_name_matching': '(?i)^totalTokenProvided$'}, {'function.writes_storage_matching': '(?i)(tiers?|sales?|totalTokenProvided|nextTierId)'}, {'function.body_contains_regex': '(?i)(tier|sale|proposal)'}, {'function.calls_function_matching': {'regex': '(?i)(safeTransferFrom|transferFrom)', 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — a-malicious-dao-pool-can-create-a-token-sale-tier-without-actual: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
