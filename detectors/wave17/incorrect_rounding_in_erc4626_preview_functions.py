"""
incorrect-rounding-in-erc4626-preview-functions — generated from reference/patterns.dsl/incorrect-rounding-in-erc4626-preview-functions.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py incorrect-rounding-in-erc4626-preview-functions.yaml
Source: hexens-glider/incorrect-rounding-direction-in-erc4626-preview-fu
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IncorrectRoundingInErc4626PreviewFunctions(AbstractDetector):
    ARGUMENT = "incorrect-rounding-in-erc4626-preview-functions"
    HELP = "ERC4626 preview function visibly uses the opposite rounding direction from the EIP-4626 expectation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/incorrect-rounding-in-erc4626-preview-functions.yaml"
    WIKI_TITLE = "Incorrect rounding in ERC4626 preview functions"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves that an ERC4626-shaped preview function visibly rounds in the wrong direction on the owned fixture pair. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "ERC4626 preview function visibly uses the opposite rounding direction from the EIP-4626 expectation."
    WIKI_RECOMMENDATION = "`previewDeposit` / `previewRedeem` should floor; `previewMint` / `previewWithdraw` should ceil. Do not promote from this fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ERC4626|IERC4626|totalAssets|convertToAssets|convertToShares'}]
    _MATCH = [{'function.name_matches': '^(previewDeposit|previewRedeem|previewMint|previewWithdraw)$'}, {'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'mulDivUp|roundUp|Rounding\\.Up|Rounding\\.Ceil|Ceil|mulDivDown|roundDown|Rounding\\.Down|Rounding\\.Floor|Floor'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — incorrect-rounding-in-erc4626-preview-functions: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
