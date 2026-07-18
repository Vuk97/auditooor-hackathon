"""
fx-euler-hook-blocks-liquidation-transfer — generated from reference/patterns.dsl/fx-euler-hook-blocks-liquidation-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-hook-blocks-liquidation-transfer.yaml
Source: auditooor-R71-fixdiff-mined-euler-periphery-aea4e026
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerHookBlocksLiquidationTransfer(AbstractDetector):
    ARGUMENT = "fx-euler-hook-blocks-liquidation-transfer"
    HELP = "Hook target's fallback/transfer check unconditionally reverts if caller hasn't signed TOS (or similar compliance gate), but does not bypass the check when EVC is in controlCollateral context. Blocks the controller from seizing collateral from a non-signing violator, making affected positions unliqui"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-hook-blocks-liquidation-transfer.yaml"
    WIKI_TITLE = "Hook target compliance gate blocks controlCollateral — unliquidatable violators create bad debt"
    WIKI_DESCRIPTION = "Vaults that install a hook target enforcing compliance (signed TOS, KYC, allowlist) on transfers MUST bypass the check when EVC is in the controlCollateral context. controlCollateral is how the liability vault pulls collateral from an insolvent borrower during liquidation; if the borrower never signed the TOS (or the TOS hash rotated without re-signing), the transfer reverts and the position becom"
    WIKI_EXPLOIT_SCENARIO = "Euler HookTargetTermsOfUse (2026-03): user deposits while current TOS is v1. Governance rotates to TOS v2; user does not re-sign. User's position becomes under-water. Liquidator calls liquidate; controller calls controlCollateral to transfer collateral shares; hook target's fallback runs _checkTermsOfUse → user has not signed v2 → revert. Position accumulates bad debt until user re-signs (they won"
    WIKI_RECOMMENDATION = "At the top of the hook fallback: `if (evc.isControlCollateralInProgress()) return;`. Or explicitly exempt `transfer` from being hookable when the hook is governance-compliance-related. All compliance / allow-list / TOS hooks must have a liquidation-bypass."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['IHookTarget', 'BaseHookTarget']}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'fallback|transfer|_checkTermsOfUse|_beforeTransfer'}, {'function.body_contains_regex': 'revert|TermsOfUseNotSigned|NotAuthorized'}, {'function.body_not_contains_regex': 'isControlCollateralInProgress|controllerAuthenticate|liquidation|EVC.*control'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-hook-blocks-liquidation-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
