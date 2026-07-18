"""
glider-anyone-can-call-erc-token-transfers — generated from reference/patterns.dsl/glider-anyone-can-call-erc-token-transfers.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-anyone-can-call-erc-token-transfers.yaml
Source: hexens-glider/anyone-can-call-erc-token-transfers
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderAnyoneCanCallErcTokenTransfers(AbstractDetector):
    ARGUMENT = "glider-anyone-can-call-erc-token-transfers"
    HELP = "Contracts that allow owners to withdraw tokens may represent backdoor functions"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-anyone-can-call-erc-token-transfers.yaml"
    WIKI_TITLE = "Contracts that allow owners to withdraw tokens may represent backdoor functions"
    WIKI_DESCRIPTION = "A contract with a backdoor function that lets the owner withdraw tokens may indicate a scam. This query identifies these backdoor functions via looking for functions that call transfer-like functions for ERC-20, ERC-721, or ERC-1155 tokens and lack modifiers that call msg.sender indicating a lack of owner check."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query anyone-can-call-erc-token-transfers. Tags: malicious logic, access control."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.calls_function_matching': '^(transfer|transferFrom|safeTransfer|safeTransferFromsafeBatchTransferFrom)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-anyone-can-call-erc-token-transfers: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
