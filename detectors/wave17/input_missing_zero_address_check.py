"""
input-missing-zero-address-check — generated from reference/patterns.dsl/input-missing-zero-address-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py input-missing-zero-address-check.yaml
Source: solodit-cluster-C0209
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InputMissingZeroAddressCheck(AbstractDetector):
    ARGUMENT = "input-missing-zero-address-check"
    HELP = "External setter / initializer writes an address parameter into storage without `require(x != address(0))`; silent zero-address misconfiguration bricks the dependent code path."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/input-missing-zero-address-check.yaml"
    WIKI_TITLE = "Missing zero-address validation on setter / initializer"
    WIKI_DESCRIPTION = "An externally callable configuration function (set*, update*, init*, change*, configure*, register*) assigns an address parameter to a storage variable without first checking that the address is non-zero. A typo or miscomputed argument silently stores address(0), and every dependent call path either reverts on interaction (permanent DoS) or — worse — interprets the zero slot as an uninitialized se"
    WIKI_EXPLOIT_SCENARIO = "A governance multisig calls `setOracle(newOracle)` with an incorrectly encoded argument that truncates to the zero address. The oracle slot is now `address(0)`. Every pricing query either reverts (locking liquidations) or returns the default zero price (mispricing collateral and enabling free liquidations). The bug is only noticed after loss is realised; recovery requires another governance round."
    WIKI_RECOMMENDATION = "Add `require(newAddr != address(0), \"zero address\")` — or a `ZeroAddress()` custom-error revert — at the top of every setter, initializer, and configuration function that stores an address parameter. Centralise the check in a `_nonZero(address)` helper or a `notZero(addr)` modifier so it cannot be"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set[A-Z][A-Za-z0-9_]+|initialize|init|__[A-Za-z0-9_]+_init|update[A-Z][A-Za-z0-9_]+|change[A-Z][A-Za-z0-9_]+|configure[A-Z][A-Za-z0-9_]*|register[A-Z][A-Za-z0-9_]*|add[A-Z][A-Za-z0-9_]+|appoint[A-Z][A-Za-z0-9_]*|grant[A-Z][A-Za-z0-9_]*|transferOwnership|transferAdmin|transferAdminship)$'}, {'function.writes_storage_matching': '.*'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[^)]*!=\\s*address\\s*\\(\\s*0x?0*\\s*\\)|if\\s*\\(\\s*[^)]*==\\s*address\\s*\\(\\s*0x?0*\\s*\\)\\s*\\)\\s*(revert|throw)|_?requireNonZero\\s*\\(|_?checkZero\\s*\\(|assert\\s*\\(\\s*[^)]*!=\\s*address\\s*\\(\\s*0x?0*\\s*\\)|ZeroAddress\\s*\\(\\s*\\)|AddressZero\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — input-missing-zero-address-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
