"""
fei-iscontract-bypass-during-construction — generated from reference/patterns.dsl/fei-iscontract-bypass-during-construction.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fei-iscontract-bypass-during-construction.yaml
Source: auditooor-R76-immunefi-fei-flashloan-$60k-ETH-at-risk
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeiIscontractBypassDuringConstruction(AbstractDetector):
    ARGUMENT = "fei-iscontract-bypass-during-construction"
    HELP = "`Address.isContract(msg.sender)` returns false during the caller's constructor. Guard is bypassed by calling from a constructor. Any flashloan-dependent invariant behind this guard is breakable."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fei-iscontract-bypass-during-construction.yaml"
    WIKI_TITLE = "isContract() guard is bypassed from within a constructor (codesize == 0)"
    WIKI_DESCRIPTION = "The OpenZeppelin `Address.isContract` helper uses `extcodesize` to detect contracts. During a contract's construction phase, its codesize is zero — so `isContract(address(this))` reads false. Any guard that uses isContract to assert an EOA caller is bypassed by placing the call inside a constructor. When the guard protects an economic invariant (bonding-curve allocate, mint, stake) that requires s"
    WIKI_EXPLOIT_SCENARIO = "Fei's BondingCurve.allocate was gated by `nonContract`. An attacker deployed a one-shot contract whose constructor: (1) flashloaned WETH, (2) dumped into ETH/FEI pool to skew price, (3) called allocate() (isContract returned false), (4) allocate deposited PCV at market price into skewed pool with 100% slippage, (5) arb'd back and repaid. ~60,000 ETH exposure."
    WIKI_RECOMMENDATION = "Use `require(msg.sender == tx.origin)` instead of isContract for strict EOA guards (still imperfect under EIP-7702 but safer than codesize). Better: remove the guard and replace with slippage-bounded-by-oracle checks. Bonding-curve / PCV allocations must compare realized fill price to oracle price a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_modifier_regex': '(?i)nonContract|onlyEOA|notContract'}, {'function.body_contains_regex': '(?i)Address\\.isContract\\s*\\(\\s*msg\\.sender\\s*\\)|msg\\.sender\\.code\\.length\\s*==\\s*0|extcodesize\\s*\\('}, {'function.body_not_contains_regex': '(?i)tx\\.origin\\s*==\\s*msg\\.sender|require\\s*\\(\\s*msg\\.sender\\s*==\\s*tx\\.origin\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fei-iscontract-bypass-during-construction: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
