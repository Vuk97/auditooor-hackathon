"""
fee-setter-no-upper-bound — generated from reference/patterns.dsl/fee-setter-no-upper-bound.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-setter-no-upper-bound.yaml
Source: solodit/excessive-fee-setting
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeSetterNoUpperBound(AbstractDetector):
    ARGUMENT = "fee-setter-no-upper-bound"
    HELP = "Fee setter writes a new fee rate with no upper-bound assertion. Governance (compromised or malicious) can set the fee to 100%, freezing user withdrawals or stealing the full principal on mint/redeem. Audit findings repeatedly flag this as `Freezing of user funds due to excessive fee settings`."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-setter-no-upper-bound.yaml"
    WIKI_TITLE = "Fee setter has no `<= MAX_FEE` guard — centralisation / fund-freeze risk"
    WIKI_DESCRIPTION = "A mutable fee (mintFee, redeemFee, protocolFee, performanceFee) is written by a privileged setter with no upper bound. A compromised governance key — or a rushed ops mistake — can set the fee to 10_000 bps (100%) or to the full precision factor (1e18), which either causes every deposit/withdraw to revert (subtraction underflow) or silently confiscates the entire amount. This is the `excessive-fee-"
    WIKI_EXPLOIT_SCENARIO = "Governance multisig is phished. Attacker proposes `setRedeemFee(10000)` via a short timelock. The proposal passes. Every subsequent `redeem()` call computes `net = gross - gross * 10000 / 10000 == 0`, silently delivering zero tokens to the user while keeping the deposit. Because there is no pause / refund path, depositors cannot recover funds without a governance reversal. A MAX_FEE cap — even a g"
    WIKI_RECOMMENDATION = "Hard-code a MAX_FEE constant in the setter: `require(newFee <= MAX_FEE, \"fee too high\")`. Pick the cap based on protocol economics (commonly 500 – 2000 bps for swap fees, 100 – 500 bps for management fees). Emit an event with old/new values for monitoring. Route fee changes through a timelock long"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '[Ff]ee|feeBps|feeRate|protocolFee|mintFee|redeemFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(setFee|setProtocolFee|setMintFee|setRedeemFee|setFeeBps|setManagementFee|setPerformanceFee|updateFee|_setFee)$'}, {'function.writes_storage_matching': '[Ff]ee'}, {'function.body_not_contains_regex': 'require\\s*\\(.*[Ff]ee\\s*<=?\\s*(MAX_FEE|MAX_BPS|10000|1e18|BASIS_POINTS|PRECISION)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*<=?\\s*[0-9]+\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-setter-no-upper-bound: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
