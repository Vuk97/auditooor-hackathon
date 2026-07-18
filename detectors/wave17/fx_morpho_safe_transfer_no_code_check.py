"""
fx-morpho-safe-transfer-no-code-check — generated from reference/patterns.dsl/fx-morpho-safe-transfer-no-code-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-morpho-safe-transfer-no-code-check.yaml
Source: github:morpho-org/morpho-blue@a4cb34b
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxMorphoSafeTransferNoCodeCheck(AbstractDetector):
    ARGUMENT = "fx-morpho-safe-transfer-no-code-check"
    HELP = "SafeTransfer/SafeTransferFrom does not check code.length before calling token address. A zero-code address (EOA or destroyed contract) returns success=true on any .call(), causing the transfer to silently succeed with no actual token movement."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-morpho-safe-transfer-no-code-check.yaml"
    WIKI_TITLE = "Safe-transfer wrapper missing code.length guard — silent no-op on EOA token address"
    WIKI_DESCRIPTION = "Custom safeTransfer/safeTransferFrom wrappers that use .call() without first verifying address(token).code.length > 0 will silently succeed when token is an EOA or a self-destructed contract. EVM returns (true, empty) for calls to addresses without code, passing all require(success) checks. Markets created with a non-existent token can be used to mint unbacked shares or drain real tokens already i"
    WIKI_EXPLOIT_SCENARIO = "Morpho cantina audit (2023): attacker enables a token address with no deployed bytecode. supply() credits shares, withdraw() calls safeTransfer which silently succeeds, allowing repeated share minting with no corresponding token deposit."
    WIKI_RECOMMENDATION = "Add `require(address(token).code.length > 0, 'no code')` as the first check in every safeTransfer/safeTransferFrom wrapper. Alternatively, use OpenZeppelin SafeERC20 which includes this guard."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^(safeTransfer|safeTransferFrom)$'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '^(safeTransfer|safeTransferFrom)$'}, {'function.has_external_call': True}, {'function.body_contains_regex': '\\.call\\('}, {'function.body_not_contains_regex': 'code\\.length|extcodesize|isContract'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-morpho-safe-transfer-no-code-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
