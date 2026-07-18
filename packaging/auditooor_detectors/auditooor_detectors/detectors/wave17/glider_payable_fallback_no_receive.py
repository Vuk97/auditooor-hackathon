"""
glider-payable-fallback-no-receive — generated from reference/patterns.dsl/glider-payable-fallback-no-receive.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-payable-fallback-no-receive.yaml
Source: glider/payable-fallback-no-receive
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPayableFallbackNoReceive(AbstractDetector):
    ARGUMENT = "glider-payable-fallback-no-receive"
    HELP = "Contract exposes a payable `fallback()` but defines no `receive()`. Plain ETH transfers (empty calldata) fall through to `fallback()` which may not be the intended entrypoint for value-only sends."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-payable-fallback-no-receive.yaml"
    WIKI_TITLE = "Payable fallback without a dedicated receive()"
    WIKI_DESCRIPTION = "Solidity routes value transfers with empty calldata to `receive()` if declared; otherwise to a payable `fallback()`. Contracts that only declare payable fallback can silently accept ETH through paths the author did not intend (e.g. selfdestruct-style force-sends, direct EOA transfers)."
    WIKI_EXPLOIT_SCENARIO = "Vault declares payable fallback for legacy router compatibility. User sends ETH directly to the vault address; fallback executes the router compat code path on empty calldata, potentially minting shares based on a stale reserve check."
    WIKI_RECOMMENDATION = "Declare `receive() external payable` explicitly and route plain transfers there. Keep `fallback()` non-payable unless it genuinely needs to accept value."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^fallback$'}, {'contract.has_no_function_body_matching': 'receive\\s*\\(\\s*\\)\\s*external\\s+payable'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^fallback$'}, {'function.is_payable': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-payable-fallback-no-receive: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
