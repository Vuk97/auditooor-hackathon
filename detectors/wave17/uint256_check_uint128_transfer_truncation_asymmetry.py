"""
uint256-check-uint128-transfer-truncation-asymmetry — generated from reference/patterns.dsl/uint256-check-uint128-transfer-truncation-asymmetry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uint256-check-uint128-transfer-truncation-asymmetry.yaml
Source: r106-centrifuge-v3-AsyncRequestManager.requestRedeem
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Uint256CheckUint128TransferTruncationAsymmetry(AbstractDetector):
    ARGUMENT = "uint256-check-uint128-transfer-truncation-asymmetry"
    HELP = "External entrypoint authorizes against a `uint256 amount` parameter but transfers / writes state using a truncated `uint128 amount_` local. If the auth check is amount-sensitive (transfer-restriction hook, allowance, max-cap), an attacker can encode `(2^128) | small` to pass the check on a huge valu"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uint256-check-uint128-transfer-truncation-asymmetry.yaml"
    WIKI_TITLE = "uint256 authorization check vs uint128 truncated transfer — restriction bypass"
    WIKI_DESCRIPTION = "Async/batched vault and ERC-1404 token request entrypoints take an `amount` parameter as `uint256` to match the ERC-7540 / ERC-4626 interface, then SafeCast it to `uint128` for storage compactness. The bug arises when the post-cast `require(_canTransfer(..., amount, ...))` style check is fed the un-cast `uint256` parameter but the subsequent `safeTransferFrom(..., amount_)` uses the cast. A custom"
    WIKI_EXPLOIT_SCENARIO = "A frozen-account hook reads `if (amount > maxFrozen[user]) return false; return amount <= softCap;`. A frozen attacker normally cannot move > softCap. They call `requestRedeem(uint256 amount = (1 << 128) | 1)`. The cast gives `amount_ = 1`. The hook is fed un-cast amount of (2^128)+1 which falls into a fall-through `else { return true; }` branch on some hook implementations (or trips overflow in t"
    WIKI_RECOMMENDATION = "Always pass the same value to the authorization check that will be used in the transfer. Either downcast first and feed `amount_` to both `_canTransfer` and the transfer call, or upcast the transfer to `uint256` (and add an explicit `require(amount <= type(uint128).max)` if storage requires it). Aud"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(request|deposit|redeem|withdraw|burn|mint|transfer)\\w*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(request\\w*|deposit\\w*|redeem\\w*|withdraw\\w*|burn\\w*|mint\\w*|transfer\\w*)'}, {'function.has_param_of_type': 'uint256'}, {'function.body_contains_regex': 'uint128\\s+\\w+_\\s*=\\s*\\w+\\s*\\.\\s*toUint128\\s*\\(\\s*\\)'}, {'function.body_contains_regex': '\\b(?:checkTransferRestriction|_canTransfer|allowance|hookCheck|checkPermission|isAllowed)\\s*\\([^)]*,\\s*([a-zA-Z][a-zA-Z0-9]*)\\s*\\)'}, {'function.body_contains_regex': '\\b(?:transfer|transferFrom|safeTransfer|safeTransferFrom|authTransferFrom|move|send|burn|mint)\\w*\\s*\\([^)]*\\w+_\\s*[,)]'}, {'function.body_not_contains_regex': '(?:checkTransferRestriction|_canTransfer|allowance|hookCheck|checkPermission|isAllowed)\\s*\\([^)]*,\\s*\\w+_\\s*\\)|(?:checkTransferRestriction|_canTransfer|allowance|hookCheck|checkPermission|isAllowed)\\s*\\([^)]*,\\s*uint(?:128|256)\\s*\\(\\s*\\w+_\\s*\\)\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uint256-check-uint128-transfer-truncation-asymmetry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
