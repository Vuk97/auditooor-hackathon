"""
r94-loop-unchecked-erc20-return — generated from reference/patterns.dsl/r94-loop-unchecked-erc20-return.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-unchecked-erc20-return.yaml
Source: loop-cycle-2-solidity-sibling-of-r94_unchecked_approve_return
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopUncheckedErc20Return(AbstractDetector):
    ARGUMENT = "r94-loop-unchecked-erc20-return"
    HELP = "NOT_SUBMIT_READY detector-fixture-smoke-only: flags bare ERC20 approve/transfer/transferFrom calls whose boolean return is discarded."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-unchecked-erc20-return.yaml"
    WIKI_TITLE = "r94-loop-unchecked-erc20-return"
    WIKI_DESCRIPTION = "Detector-fixture-smoke-only. NOT_SUBMIT_READY. This row proves only the owned Solidity shape where a bare ERC20 approve/transfer/transferFrom call is made without checking the bool return or using SafeERC20."
    WIKI_EXPLOIT_SCENARIO = "A state-mutating function calls `IERC20(token).transfer(...)` or `IERC20(token).approve(...)` directly and ignores the returned bool. On non-standard ERC20s that return false instead of reverting, the protocol updates local accounting as if the transfer or approval succeeded, even though the token operation failed."
    WIKI_RECOMMENDATION = "Use SafeERC20.safeTransfer / safeTransferFrom / forceApprove, or wrap the call in require(...). Keep this row NOT_SUBMIT_READY until broader evidence exists beyond the fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(approve|transfer|increaseAllowance|decreaseAllowance)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.source_matches_regex': '\\b(IERC20|IERC20Upgradeable|ERC20|ERC20Upgradeable|IERC20Permit|\\w+Token)\\s*\\([^)]*\\)\\s*\\.(approve|transfer|transferFrom|increaseAllowance|decreaseAllowance)\\s*\\([^;]*?\\)\\s*;\\n'}, {'function.not_source_matches_regex': '\\b(safeTransfer|safeTransferFrom|safeApprove|forceApprove|safeIncreaseAllowance|safeDecreaseAllowance)\\b'}, {'function.not_source_matches_regex': 'require\\s*\\(\\s*\\w+\\s*\\(\\s*[^)]*\\)\\s*\\.(approve|transfer|transferFrom|increaseAllowance|decreaseAllowance)\\s*\\('}, {'function.not_source_matches_regex': '\\bbool\\s+\\w+\\s*=\\s*[^;]*?\\.(approve|transfer|transferFrom|increaseAllowance|decreaseAllowance)\\s*\\('}]

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
                info = [f, f" — r94-loop-unchecked-erc20-return: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
