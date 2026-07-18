"""
payable-transfer-2300-gas-limit — generated from reference/patterns.dsl/payable-transfer-2300-gas-limit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py payable-transfer-2300-gas-limit.yaml
Source: solodit-cluster/C0142
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PayableTransfer2300GasLimit(AbstractDetector):
    ARGUMENT = "payable-transfer-2300-gas-limit"
    HELP = "Function uses payable(recipient).transfer(...) or .send(...), forwarding only 2300 gas — fails for Gnosis Safes, smart-contract wallets, and any receiver whose fallback/receive costs more than 2300 gas. Use .call{value: amt}(\"\") with return-value check."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/payable-transfer-2300-gas-limit.yaml"
    WIKI_TITLE = "Use of deprecated payable(addr).transfer / .send forwards only 2300 gas"
    WIKI_DESCRIPTION = "Solidity's `address.transfer(value)` and `address.send(value)` forward a hard-coded 2300-gas stipend to the recipient's receive/fallback function. This stipend was calibrated for the pre-EIP-1884 gas schedule and is unreliable today. Receivers that will fail include: Gnosis Safe multisigs (require ~6500 gas just to enter fallback), most smart-contract wallets (Argent, Ambire, Soul, Braavos-style),"
    WIKI_EXPLOIT_SCENARIO = "A marketplace contract calls `payable(seller).transfer(proceeds)` to pay out a sale. The seller is a Gnosis Safe. Entry into the Safe's fallback consumes more than 2300 gas before any logic runs, so the transfer reverts. The entire purchase transaction reverts; the sale can never settle while the seller's address is the Safe. Worse, in a refund path the buyer's funds become permanently locked: eac"
    WIKI_RECOMMENDATION = "Replace `payable(x).transfer(v)` with `(bool ok, ) = payable(x).call{value: v}(\"\"); require(ok, \"send failed\");`. This forwards all remaining gas (callers should protect against reentrancy via CEI or ReentrancyGuard) and is compatible with every receiver type. For pull-over-push patterns (prefer"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.not_slither_synthetic': True}, {'function.body_contains_regex': 'payable\\s*\\(\\s*\\w+\\s*\\)\\s*\\.transfer\\s*\\(|payable\\s*\\(\\s*\\w+\\s*\\)\\s*\\.send\\s*\\('}, {'function.body_not_contains_regex': '\\.call\\s*\\{\\s*value\\s*:'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — payable-transfer-2300-gas-limit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
