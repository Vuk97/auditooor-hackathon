"""
permit-frontrun-dos — generated from reference/patterns.dsl/permit-frontrun-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permit-frontrun-dos.yaml
Source: solodit-cross-cluster-standard-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PermitFrontrunDos(AbstractDetector):
    ARGUMENT = "permit-frontrun-dos"
    HELP = "ERC20 permit() invoked inside a user-facing action without try/catch — a mempool observer can front-run by submitting the victim's permit first, consuming the nonce and reverting the victim's tx (UX denial of service)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permit-frontrun-dos.yaml"
    WIKI_TITLE = "ERC20 permit front-run DoS: unwrapped permit() call reverts when nonce is stolen"
    WIKI_DESCRIPTION = "The ERC20 permit signature scheme authenticates the spender approval via an off-chain signature that advances an on-chain nonce. A permit signature is a public mempool artifact the moment the victim broadcasts it. Any observer can extract `(owner, spender, value, deadline, v, r, s)`, submit it directly to the token contract, and advance the nonce. The victim's subsequent permit() call reverts beca"
    WIKI_EXPLOIT_SCENARIO = "Alice signs a permit granting DepositZap spender rights over 100 USDC and submits `zapDeposit(..., v, r, s)` to a DeFi protocol. Eve watches the mempool, extracts the permit, and submits `USDC.permit(Alice, DepositZap, 100, deadline, v, r, s)` directly in a block that lands before Alice's. When Alice's transaction executes, her `zapDeposit` calls `USDC.permit(...)` again with the same nonce. ERC20"
    WIKI_RECOMMENDATION = "Wrap every permit() call in try/catch and silently continue when it reverts. The spender allowance will still be set (either by the attacker's front-run or by Alice's own call, whichever landed). Pattern: `try IERC20Permit(token).permit(owner, spender, value, deadline, v, r, s) {} catch {}` followed"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.permit\\s*\\(|IERC20Permit\\.permit|IPermit2\\.permit'}, {'function.body_not_contains_regex': 'try\\s+\\w+\\.permit|try\\s+IERC20Permit|catch\\s*\\{|_callPermit'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permit-frontrun-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
