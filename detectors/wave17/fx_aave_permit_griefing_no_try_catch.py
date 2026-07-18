"""
fx-aave-permit-griefing-no-try-catch — generated from reference/patterns.dsl/fx-aave-permit-griefing-no-try-catch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-aave-permit-griefing-no-try-catch.yaml
Source: github:aave-dao/aave-v3-origin@3bdd8c7
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxAavePermitGriefingNoTryCatch(AbstractDetector):
    ARGUMENT = "fx-aave-permit-griefing-no-try-catch"
    HELP = "Calling permit() directly without try/catch allows a front-running griefing attack: an attacker watches the mempool for a permit-and-withdraw transaction, front-runs the permit() call, and the victim's permit call reverts (nonce already used), blocking the withdrawal."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-aave-permit-griefing-no-try-catch.yaml"
    WIKI_TITLE = "permit() called without try/catch — front-running griefing blocks withdrawals"
    WIKI_DESCRIPTION = "ERC20 permit functions that call token.permit() directly will revert if the permit has already been used (e.g., by a front-runner who called permit separately). Wrapping the permit call in try/catch allows the function to proceed even if the permit was already applied — the transferFrom will still enforce the allowance, so no security is lost."
    WIKI_EXPLOIT_SCENARIO = "Aave v3 Sherlock audit (2024): user submits withdrawETHWithPermit(). Attacker front-runs with a standalone permit() call using the same signature, consuming the nonce. User's transaction reverts on the permit() call, blocking their withdrawal even though they have a valid signed permit."
    WIKI_RECOMMENDATION = "Wrap permit calls in try/catch: `try token.permit(owner, spender, amount, deadline, v, r, s) {} catch {}`. The downstream transferFrom will still revert if the allowance was not granted, preserving security while eliminating griefing."

    _PRECONDITIONS = [{'contract.has_function_matching': '^withdrawETH$|^withdrawETHWithPermit$'}, {'contract.source_matches_regex': '(WETHGateway|WrappedTokenGateway|PermitGateway|WithdrawETH|AaveV\\d|Pool|LendingPool|Router|SwapRouter|repay|withdraw)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdrawETH|withdrawETHWithPermit|withdrawWithPermit|repayWithPermit|supplyWithPermit|repayETHWithPermit|redeemWithPermit|permitAndWithdraw|permitWithdraw)\\w*$'}, {'function.body_contains_regex': '\\.permit\\('}, {'function.body_not_contains_regex': 'try\\s+.*\\.permit|catch'}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|SafePermit\\.permit|safePermit\\s*\\(|Permit2\\.permit|allowance\\s*\\([^)]+\\)\\s*>=|try\\s*\\{[^}]*\\.permit|try\\s+\\w+\\.permit|catch\\s*\\{|internal\\s+pure|internal\\s+view|onlyOwner|onlyPermit2)'}]

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
                info = [f, f" — fx-aave-permit-griefing-no-try-catch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
