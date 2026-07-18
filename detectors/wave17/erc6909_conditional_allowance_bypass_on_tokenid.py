"""
erc6909-conditional-allowance-bypass-on-tokenid — generated from reference/patterns.dsl/erc6909-conditional-allowance-bypass-on-tokenid.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc6909-conditional-allowance-bypass-on-tokenid.yaml
Source: r106-centrifuge-v3-BalanceSheet.deposit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc6909ConditionalAllowanceBypassOnTokenid(AbstractDetector):
    ARGUMENT = "erc6909-conditional-allowance-bypass-on-tokenid"
    HELP = "Multi-asset entrypoint dispatches `if (tokenId == 0) safeTransferFrom; else IERC6909.transferFrom(...)`. The ERC-20 branch is allowance-checked by spec; the ERC-6909 branch relies on the token's own check. With custom or upgradeable 6909 implementations, this allows a privileged manager / module to "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc6909-conditional-allowance-bypass-on-tokenid.yaml"
    WIKI_TITLE = "Conditional ERC-20 vs ERC-6909 dispatch skips local allowance check"
    WIKI_DESCRIPTION = "A multi-token vault `deposit(address asset, uint256 tokenId, address from, uint128 amount)` distinguishes ERC-20 from ERC-6909 by `tokenId == 0`. The ERC-20 leg uses `SafeTransferLib.safeTransferFrom` which consults `allowance(from, msg.sender)`. The ERC-6909 leg calls `IERC6909(asset).transferFrom(from, to, tokenId, amount)`. ERC-6909 reference defines `setOperator` and per-id allowance, but cust"
    WIKI_EXPLOIT_SCENARIO = "Pool A's manager has manager role on the BalanceSheet contract. The custom share-token 6909 implementation grants the BalanceSheet itself a built-in operator slot for all token holders (a design simplification for cross-chain operations). Manager calls `deposit(shareToken, scId, victimUser, 1000e18)`. The dispatch hits the 6909 branch; `IERC6909(shareToken).transferFrom(victimUser, escrow, scId, 1"
    WIKI_RECOMMENDATION = "Always enforce a local allowance check in the calling contract regardless of which token leg is taken. For ERC-6909, explicitly read `IERC6909(asset).allowance(from, address(this), tokenId)` (or `isOperator`) and require it covers `amount`, OR replace `from` with `msg.sender` and refuse to honour th"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(deposit|transfer|recover|withdraw|move)\\w*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'if\\s*\\(\\s*tokenId\\s*==\\s*0\\s*\\)'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\([^)]+\\)'}, {'function.body_contains_regex': 'IERC6909\\s*\\(\\s*\\w+\\s*\\)\\s*\\.\\s*transferFrom\\s*\\([^)]+\\)'}, {'function.body_not_contains_regex': '\\b(?:allowance|_spendAllowance|_checkAllowance|approveAmount|operator)\\s*\\(\\s*\\w+\\s*,\\s*\\w+'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc6909-conditional-allowance-bypass-on-tokenid: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
