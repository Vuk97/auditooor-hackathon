"""
glider-erc165-self-identification-missing — generated from reference/patterns.dsl/glider-erc165-self-identification-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-erc165-self-identification-missing.yaml
Source: hexens-glider/non-compliant-erc165-self-identification
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderErc165SelfIdentificationMissing(AbstractDetector):
    ARGUMENT = "glider-erc165-self-identification-missing"
    HELP = "`supportsInterface` uses explicit `==` comparisons on interface ids but never claims support for the ERC-165 id itself (`0x01ffc9a7`). Violates the spec and makes the contract look non-compliant to indexers and marketplaces."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-erc165-self-identification-missing.yaml"
    WIKI_TITLE = "supportsInterface omits the ERC-165 id"
    WIKI_DESCRIPTION = "ERC-165 requires a contract advertising interface detection to return true for its own id `0x01ffc9a7`. If a contract returns true only for `IERC721`, `IERC1155`, etc. but not `IERC165`, interoperability tools treat it as a half-compliant implementation and may refuse to interact."
    WIKI_EXPLOIT_SCENARIO = "NFT marketplace does `if (!IERC165(c).supportsInterface(type(IERC165).interfaceId)) revert; if (IERC165(c).supportsInterface(type(IERC721).interfaceId)) useERC721Path();`. Victim contract returns true for IERC721 but false for IERC165, first check reverts, marketplace never lists the collection."
    WIKI_RECOMMENDATION = "Include ERC-165 in every supportsInterface implementation: `interfaceId == type(IERC165).interfaceId` (or literally `0x01ffc9a7`). OZ's `ERC165` base already does this correctly."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^supportsInterface$'}]
    _MATCH = [{'function.name_matches': '^supportsInterface$'}, {'function.kind': 'external_or_public'}, {'function.body_contains_regex': '=='}, {'function.body_not_contains_regex': 'type\\s*\\(\\s*IERC165\\s*\\)|0x01ffc9a7|interfaceId\\s*==\\s*bytes4\\s*\\(\\s*0x01ffc9a7\\s*\\)|supportsInterface\\.selector'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-erc165-self-identification-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
