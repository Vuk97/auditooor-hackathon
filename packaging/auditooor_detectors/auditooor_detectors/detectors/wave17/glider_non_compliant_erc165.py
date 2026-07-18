"""
glider-non-compliant-erc165 — generated from reference/patterns.dsl/glider-non-compliant-erc165.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-non-compliant-erc165.yaml
Source: glider-query-db/non-compliant-erc165-self-identification
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderNonCompliantErc165(AbstractDetector):
    ARGUMENT = "glider-non-compliant-erc165"
    HELP = "ERC165 `supportsInterface` does not return `true` for the ERC165 interface itself. Spec requires every ERC165 contract to report `0x01ffc9a7`."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-non-compliant-erc165.yaml"
    WIKI_TITLE = "ERC165 supportsInterface missing self-identification"
    WIKI_DESCRIPTION = "ERC165 requires every compliant contract to return `true` for `supportsInterface(0x01ffc9a7)`. Without this, introspection tools and wallets detect the contract as non-compliant, breaking integrations."
    WIKI_EXPLOIT_SCENARIO = "Marketplace checks `nft.supportsInterface(0x01ffc9a7)` before allowing listing; contract returns false; NFT cannot be listed despite being functional."
    WIKI_RECOMMENDATION = "Include `interfaceId == type(IERC165).interfaceId` (or `0x01ffc9a7`) in the supported set."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'supportsInterface'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^supportsInterface$'}, {'function.body_contains_regex': 'interfaceId\\s*=='}, {'function.body_not_contains_regex': 'type\\s*\\(\\s*IERC165\\s*\\)\\.interfaceId|0x01ffc9a7'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — glider-non-compliant-erc165: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
