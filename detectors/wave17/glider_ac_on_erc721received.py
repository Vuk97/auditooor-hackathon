"""
glider-ac-on-erc721received — generated from reference/patterns.dsl/glider-ac-on-erc721received.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-ac-on-erc721received.yaml
Source: hexens-glider/ac-on-erc721received
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderAcOnErc721received(AbstractDetector):
    ARGUMENT = "glider-ac-on-erc721received"
    HELP = "Missing Access Control in onERC721Received with State Changes"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-ac-on-erc721received.yaml"
    WIKI_TITLE = "Missing Access Control in onERC721Received with State Changes"
    WIKI_DESCRIPTION = "Identifies onERC721Received callback functions that perform state-changing operations but lack proper access control (msg.sender validation or modifiers). This can allow malicious actors to trigger unintended state changes by transferring NFTs to the vulnerable contract."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query ac-on-erc721received. Tags: access-control, erc721, nft, callback, state-modification."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'function.is_mutating': True}, {'contract.source_matches_regex': '(ERC721Holder|ERC721Receiver|IERC721Receiver|onERC721Received|ERC721TokenReceiver)'}]
    _MATCH = [{'function.name_matches': '^onERC721Received$'}, {'function.kind': 'external_or_public'}, {'function.body_contains_regex': '=\\s*msg\\.sender|balances\\[|\\+\\+|--|\\.push\\s*\\(|mint\\s*\\(|deposits\\[|\\w+\\s*=\\s*\\w+\\s*\\+|storage\\s+\\w+'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\(\\s*msg\\.sender\\s*==|onlyRole|onlyOwner|onlyController|_checkRole|hasRole\\s*\\(|whitelist\\[\\s*msg\\.sender\\s*\\]|allowedCallers\\[\\s*msg\\.sender\\s*\\])'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|internal\\s+view|internal\\s+pure|return\\s+this\\.onERC721Received\\.selector\\s*;\\s*\\}|return\\s+IERC721Receiver\\.onERC721Received\\.selector\\s*;\\s*\\}|msg\\.sender\\s*==\\s*expected|authorized\\[\\s*msg\\.sender|require\\s*\\(\\s*operator\\s*==)'}]

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
                info = [f, f" — glider-ac-on-erc721received: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
