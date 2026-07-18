"""
erc20-approve-frontrun-allowance-change — generated from reference/patterns.dsl/erc20-approve-frontrun-allowance-change.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc20-approve-frontrun-allowance-change.yaml
Source: solodit-cluster/C0235
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc20ApproveFrontrunAllowanceChange(AbstractDetector):
    ARGUMENT = "erc20-approve-frontrun-allowance-change"
    HELP = "ERC20 token implementation exposes the classic `approve(spender, amount)` race — spender can front-run the new allowance with a transferFrom draining the old one, then pull the new allowance on top. No `increaseAllowance` / `permit` / `_approve(_,0)` mitigations found in the approve body."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc20-approve-frontrun-allowance-change.yaml"
    WIKI_TITLE = "ERC20 token: approve() vulnerable to allowance front-running race"
    WIKI_DESCRIPTION = "The token's `approve(spender, amount)` overwrites the spender's allowance without a preceding zero reset and without exposing the race-safe `increaseAllowance` / `decreaseAllowance` or `permit` wrappers. A spender monitoring the mempool can transferFrom the OLD allowance before the new `approve` confirms, then transferFrom the NEW allowance once the update lands — draining (old + new) instead of m"
    WIKI_EXPLOIT_SCENARIO = "Alice granted Bob an allowance of 100 TOKEN. Alice wants to reduce Bob's allowance to 20 TOKEN and submits `approve(bob, 20)`. Bob's bot sees the pending transaction in the mempool, front-runs it with `transferFrom(alice, bob, 100)` at a higher gas price, then — once Alice's `approve(bob, 20)` confirms — immediately pulls another 20 TOKEN. Net transfer: 120 TOKEN instead of the 20 Alice intended. "
    WIKI_RECOMMENDATION = "Expose `increaseAllowance(spender, addedValue)` and `decreaseAllowance(spender, subtractedValue)` that compute the delta atomically instead of overwriting. For off-chain signed approvals, implement EIP-2612 `permit`. If staying on plain `approve`, callers must be educated to send `approve(spender, 0"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^approve$'}, {'contract.has_state_var_matching': 'allowance|_allowances|allowances'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^approve$'}, {'function.writes_storage_matching': 'allowance|_allowances'}, {'function.body_not_contains_regex': 'forceApprove|increaseAllowance|decreaseAllowance|safeIncreaseAllowance|permit|_approve\\s*\\(.*,\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc20-approve-frontrun-allowance-change: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
