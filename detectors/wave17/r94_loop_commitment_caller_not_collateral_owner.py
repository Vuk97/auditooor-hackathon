"""
r94-loop-commitment-caller-not-collateral-owner — generated from reference/patterns.dsl/r94-loop-commitment-caller-not-collateral-owner.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-commitment-caller-not-collateral-owner.yaml
Source: loop-cycle-50-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopCommitmentCallerNotCollateralOwner(AbstractDetector):
    ARGUMENT = "r94-loop-commitment-caller-not-collateral-owner"
    HELP = "r94-loop-commitment-caller-not-collateral-owner"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-commitment-caller-not-collateral-owner.yaml"
    WIKI_TITLE = "r94-loop-commitment-caller-not-collateral-owner"
    WIKI_DESCRIPTION = "r94-loop-commitment-caller-not-collateral-owner"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-commitment-caller-not-collateral-owner"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(validateCommitment|commitToLien|openLien)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(validateCommitment|openLien|commitToLien|commitLoan|validateLoan|borrowOnBehalf|startCommitment)'}, {'function.source_matches_regex': '\\|\\|\\s*(ECDSA\\.recover|\\w+\\.verify|msgSender\\s*\\(\\s*\\)\\s*==)'}, {'function.not_source_matches_regex': '(collateralOwner|nftOwner|tokenOwner|ownerOf\\s*\\([^)]*\\)\\s*==\\s*msgSender)'}]

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
                info = [f, f" — r94-loop-commitment-caller-not-collateral-owner: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
