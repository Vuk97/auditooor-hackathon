"""
narrow-uint-param-for-unbounded-id — generated from reference/patterns.dsl/narrow-uint-param-for-unbounded-id.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py narrow-uint-param-for-unbounded-id.yaml
Source: solodit-32188-ai-arena-fighter-farm-reroll
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NarrowUintParamForUnboundedId(AbstractDetector):
    ARGUMENT = "narrow-uint-param-for-unbounded-id"
    HELP = "narrow-uint-param-for-unbounded-id"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/narrow-uint-param-for-unbounded-id.yaml"
    WIKI_TITLE = "narrow-uint-param-for-unbounded-id"
    WIKI_DESCRIPTION = "narrow-uint-param-for-unbounded-id"
    WIKI_EXPLOIT_SCENARIO = "narrow-uint-param-for-unbounded-id"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ERC721|ERC1155|NFT|Token|Fighter|Card|Item)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_name_matching': '(?i)(tokenId|nftId|itemId|^id$)'}, {'function.body_contains_regex': '(function\\s+\\w+\\s*\\([^)]*\\buint(?:8|16)\\b\\s+(?:tokenId|nftId|itemId|id)\\b)'}, {'function.body_contains_regex': '(_tokenIdCounter|totalSupply\\s*\\+\\+|_mint\\s*\\(|_safeMint\\s*\\(|nextId\\s*\\+\\+|_nextTokenId)'}, {'function.body_not_contains_regex': '(require\\s*\\(\\s*\\w+\\s*<\\s*(?:256|65536|type\\s*\\(\\s*uint(?:8|16)\\s*\\)\\s*\\.max)|tokenId\\s*<\\s*256)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — narrow-uint-param-for-unbounded-id: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
