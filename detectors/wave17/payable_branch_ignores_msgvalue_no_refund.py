"""
payable-branch-ignores-msgvalue-no-refund — generated from reference/patterns.dsl/payable-branch-ignores-msgvalue-no-refund.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py payable-branch-ignores-msgvalue-no-refund.yaml
Source: auditooor-R67-snowbridge-L2Adaptor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PayableBranchIgnoresMsgvalueNoRefund(AbstractDetector):
    ARGUMENT = "payable-branch-ignores-msgvalue-no-refund"
    HELP = "Payable function branches on input parameter; one branch consumes msg.value via {value:…} call, another pulls ERC20 via safeTransferFrom and does NOT consume msg.value. Refund gate excludes the non-consuming branch. Users who enter the non-consuming branch with attached msg.value silently lose that "
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/payable-branch-ignores-msgvalue-no-refund.yaml"
    WIKI_TITLE = "Payable function branch ignores msg.value without refund"
    WIKI_DESCRIPTION = "The function is payable and dispatches on an input-token / mode parameter. The native-ETH branch consumes msg.value correctly via `target.deposit{value: amount}()` and refunds excess at the end. The ERC20/token branch pulls funds via `safeTransferFrom(msg.sender, address(this), ...)` and never inspects, consumes, or refunds msg.value. The refund block at the end of the function is conjunct-gated o"
    WIKI_EXPLOIT_SCENARIO = "A bridge adaptor exposes `sendEtherAndCall(...)` as `payable` and accepts either native ETH or WETH as input. A user wallet or batching contract sends 0.5 ETH along with a WETH-mode call (e.g. to pre-fund fees); the WETH branch runs, pulls the WETH via safeTransferFrom, and the 0.5 ETH silently accumulates in the adaptor. The adaptor has no rescue/withdraw/owner — the 0.5 ETH is permanently locked"
    WIKI_RECOMMENDATION = "Add `require(msg.value == 0, 'msg.value must be zero for ERC20 input')` at the top of the non-consuming branch. Alternative: extend the refund gate to `if (msg.value > 0 && msg.value > <consumed>) { refund; }` regardless of input-token, so stray ETH is always returned rather than trapped."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.body_contains_regex': '\\{\\s*value\\s*:\\s*[a-zA-Z_][a-zA-Z0-9_.]*\\s*\\}\\s*\\('}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\(\\s*msg\\.sender\\s*,\\s*address\\s*\\(\\s*this\\s*\\)|transferFrom\\s*\\(\\s*msg\\.sender\\s*,\\s*address\\s*\\(\\s*this\\s*\\)'}, {'function.body_contains_regex': 'if\\s*\\(.*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*&&\\s*msg\\.value'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.value\\s*==\\s*0\\s*[,)]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — payable-branch-ignores-msgvalue-no-refund: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
