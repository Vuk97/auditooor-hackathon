"""
fx-euler-synth-self-not-excluded-supply — generated from reference/patterns.dsl/fx-euler-synth-self-not-excluded-supply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-synth-self-not-excluded-supply.yaml
Source: github:euler-xyz/euler-vault-kit@06cc3c0
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerSynthSelfNotExcludedSupply(AbstractDetector):
    ARGUMENT = "fx-euler-synth-self-not-excluded-supply"
    HELP = "Synthetic ERC20 contracts that exclude certain addresses from totalSupply (e.g., to avoid double-counting) must add address(this) to the exclusion set during construction. If omitted, minting to the contract itself inflates totalSupply and corrupts collateral accounting."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-synth-self-not-excluded-supply.yaml"
    WIKI_TITLE = "Synthetic ERC20 constructor missing self-exclusion from totalSupply tracking — inflated supply on self-mint"
    WIKI_DESCRIPTION = "ERC20 synths that maintain an ignoredForTotalSupply set (addresses whose balances are subtracted from the reported total) must include address(this) during construction. If the contract mints to itself (e.g., for liquidity seeding or internal accounting), that balance inflates the reported totalSupply, corrupting any collateral factor or utilization ratio computed against it."
    WIKI_EXPLOIT_SCENARIO = "Euler Cantina-68 (2024): ESynth constructor did not add address(this) to ignoredForTotalSupply. Internal mint operations inflated totalSupply, causing external integrators querying totalSupply to over-estimate circulating supply."
    WIKI_RECOMMENDATION = "In the synth constructor, call `ignoredForTotalSupply.add(address(this))` immediately after initialization so the contract's own balance is always excluded from the circulating supply."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^totalSupply$|^mint$'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'constructor|initialize'}, {'function.body_not_contains_regex': 'ignoredForTotalSupply|excludeFromSupply|add\\(address\\(this\\)\\)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-synth-self-not-excluded-supply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
