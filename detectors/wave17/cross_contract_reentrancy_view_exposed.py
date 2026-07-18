"""
cross-contract-reentrancy-view-exposed — generated from reference/patterns.dsl/cross-contract-reentrancy-view-exposed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-contract-reentrancy-view-exposed.yaml
Source: solodit/balancer-readonly-reentrancy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossContractReentrancyViewExposed(AbstractDetector):
    ARGUMENT = "cross-contract-reentrancy-view-exposed"
    HELP = "View function exposes reserve/balance/totalSupply state that can be observed mid-mutation during a callback (ERC20/721/1155/flash-loan). Third-party consumers (oracles, vaults) reading this view during the callback receive stale values and can be manipulated."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-contract-reentrancy-view-exposed.yaml"
    WIKI_TITLE = "Read-only cross-contract reentrancy via exposed view of callback-mutated state"
    WIKI_DESCRIPTION = "The contract receives external callbacks (token hook, flash loan, low-level .call) and mutates reserve/balance/supply state inside or after that callback. A view function exposes that same state without any reentrancy guard. An external consumer that queries the view from inside the callback reads a transient, inconsistent snapshot of the pool — classic Balancer-style read-only cross-contract reen"
    WIKI_EXPLOIT_SCENARIO = "Attacker initiates a callback-triggering flow (e.g. flash loan, ERC777 send, ERC1155 safeTransferFrom). During the hook, attacker calls an external lending market or oracle that prices collateral by reading this contract's exposed view (getReserves / pricePerShare / totalSupply). The view returns stale values because the callback ran before the pool finished mutating its state. Attacker borrows ag"
    WIKI_RECOMMENDATION = "Guard exposed view accessors with the same reentrancy lock used on mutating functions (e.g. OZ ReentrancyGuard with `nonReentrantView` pattern), or ensure all state writes complete before any external callback returns. Alternatively, require consumers to pull prices from a checkpointed, lock-aware a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'onERC(20|721|1155)|IFlashLoan|\\.call\\{|callback|onFlashLoan|onHook'}, {'contract.has_function_matching': 'getReserves|getBalance|totalSupply|pricePerShare|convertToAssets|balanceOf'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\bview\\b|\\bpure\\b'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'reserve|balance|totalSupply|totalAssets|sharePrice|pricePerShare|virtualPrice'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — cross-contract-reentrancy-view-exposed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
