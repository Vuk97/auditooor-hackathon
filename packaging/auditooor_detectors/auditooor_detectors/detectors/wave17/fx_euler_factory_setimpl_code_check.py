"""
fx-euler-factory-setimpl-code-check — generated from reference/patterns.dsl/fx-euler-factory-setimpl-code-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-factory-setimpl-code-check.yaml
Source: github:euler-xyz/euler-vault-kit@b5fc6f2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerFactorySetimplCodeCheck(AbstractDetector):
    ARGUMENT = "fx-euler-factory-setimpl-code-check"
    HELP = "setImplementation() checks address(0) but not code.length. An EOA address or a future self-destructed contract passes the zero-check, pointing all beacon proxies at a non-contract and permanently bricking upgrades."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-factory-setimpl-code-check.yaml"
    WIKI_TITLE = "Factory setImplementation only checks address(0), not code.length — EOA implementation bricks beacon proxies"
    WIKI_DESCRIPTION = "Factory upgrade functions that guard with `if (newImpl == address(0)) revert` accept any non-zero address, including EOAs and self-destructed contracts. All beacon proxies immediately delegate to the new address; delegatecall to an EOA returns empty and will revert or silently no-op, permanently bricking all proxies pointed at that factory."
    WIKI_EXPLOIT_SCENARIO = "Euler Cantina-320 (2024): governance calls setImplementation(eoaAddr). All GenericFactory-spawned EVaults immediately point to eoaAddr. Every interaction with any vault reverts on the delegatecall, with no recovery path because the storage slot is already overwritten."
    WIKI_RECOMMENDATION = "Replace `if (newImplementation == address(0)) revert` with `if (newImplementation.code.length == 0) revert` to reject EOAs and empty accounts in addition to the zero address."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^setImplementation$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^setImplementation$'}, {'function.body_contains_regex': '== address\\(0\\)|!= address\\(0\\)'}, {'function.body_not_contains_regex': 'code\\.length|extcodesize'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-factory-setimpl-code-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
