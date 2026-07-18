"""
wrapped-collateral-no-recovery-function — generated from reference/patterns.dsl/wrapped-collateral-no-recovery-function.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py wrapped-collateral-no-recovery-function.yaml
Source: auditooor-R77-polymarket-WrappedCollateral
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WrappedCollateralNoRecoveryFunction(AbstractDetector):
    ARGUMENT = "wrapped-collateral-no-recovery-function"
    HELP = "ERC20 wrapper contract has wrap/unwrap but no recover/rescue/sweep function for accidentally-sent underlying tokens."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/wrapped-collateral-no-recovery-function.yaml"
    WIKI_TITLE = "WrappedCollateral lacks recovery for mis-sent underlying"
    WIKI_DESCRIPTION = "WrappedCollateral is an ERC20 wrapper that mints wrapped tokens when collateral is deposited and burns them on unwrap. Users or integrations may accidentally send the underlying ERC20 directly to the contract. Without a rescue/recover/sweep function, those tokens are permanently locked."
    WIKI_EXPLOIT_SCENARIO = "A user sends USDC directly to WrappedCollateral instead of calling wrap(). The USDC is now stuck in the contract with no function to extract it. The contract owner can mint/burn wrapped tokens but cannot recover the raw underlying."
    WIKI_RECOMMENDATION = "Add an `onlyOwner` `rescueTokens(address token, address to, uint256 amount)` function that can recover accidentally-sent ERC20s."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)function\\s+wrap\\s*\\(|function\\s+unwrap\\s*\\('}, {'contract.source_matches_regex': '(?i)_mint|_burn|ERC20|underlying'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(wrap|unwrap|mint|burn)'}, {'contract.has_no_function_body_matching': '(?i)function\\s+(rescue|recover|sweep|withdraw|drain)\\s*\\([^)]*token|function\\s+(rescue|recover|sweep|withdraw|drain)\\s*\\([^)]*underlying'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — wrapped-collateral-no-recovery-function: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
