"""
fx-euler-erc4626-view-readonly-reentrancy-unguarded — generated from reference/patterns.dsl/fx-euler-erc4626-view-readonly-reentrancy-unguarded.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-erc4626-view-readonly-reentrancy-unguarded.yaml
Source: auditooor-R71-fixdiff-mined-euler-periphery-4caf1a85
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerErc4626ViewReadonlyReentrancyUnguarded(AbstractDetector):
    ARGUMENT = "fx-euler-erc4626-view-readonly-reentrancy-unguarded"
    HELP = "ERC-4626 view functions (totalSupply, totalAssets, balanceOf, convertTo*, preview*) lack a view-reentrancy guard; external protocols reading them during the reentrancy window observe inconsistent intermediate state, enabling read-only reentrancy."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-erc4626-view-readonly-reentrancy-unguarded.yaml"
    WIKI_TITLE = "ERC-4626 view functions missing read-only reentrancy guard — stale share price during state transitions"
    WIKI_DESCRIPTION = "ERC-4626-style vaults with reentrancy-locked mutating paths MUST also guard price-exposing view functions (totalAssets, totalSupply, convertToAssets, previewDeposit) against read-only reentrancy. When mid-state read is possible (asset has transfer callback, ERC-777/permit2 token, or a cross-contract pricing oracle reads the vault), an outside protocol observes an inflated share price and mints/liq"
    WIKI_EXPLOIT_SCENARIO = "Euler evk-periphery Securitize vault (2025-10): ERC-4626 totalAssets lacked nonReentrantView. During deposit with a token whose transfer hook reenters another protocol that queries this vault's totalAssets via convertToAssets, the reader sees assets incremented but shares not yet minted — a 2-wei inflated share price. An attacker mints an oracle-priced position at the stale rate and pockets the di"
    WIKI_RECOMMENDATION = "Add `nonReentrantView` modifier on all externally-visible price/balance views. Use a selector-scoped variant so internal view-to-view calls still work: `modifier nonReentrantView(bytes4 selector) { if (bytes4(msg.data[:4]) == selector && _isEnabled(REENTRANCY)) revert Reentrancy(); _; }`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['ERC4626', 'ERC4626EVC']}, {'contract.has_state_var_matching': 'REENTRANCY|_locked|_status'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(totalSupply|totalAssets|balanceOf|convertToAssets|convertToShares|previewDeposit|previewMint|previewRedeem|previewWithdraw|allowance|accountAssets)$'}, {'function.body_not_contains_regex': 'nonReentrantView|_isEnabled\\s*\\(\\s*REENTRANCY|_locked\\s*==|_status\\s*=='}, {'function.body_not_contains_regex': 'selector.*REENTRANCY'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-erc4626-view-readonly-reentrancy-unguarded: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
