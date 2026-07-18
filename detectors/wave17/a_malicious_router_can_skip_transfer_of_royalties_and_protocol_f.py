"""
a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f — generated from reference/patterns.dsl/a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousRouterCanSkipTransferOfRoyaltiesAndProtocolF(AbstractDetector):
    ARGUMENT = "a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f"
    HELP = "A malicious router can skip transfer of royalties and protocol fee"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f.yaml"
    WIKI_TITLE = "A malicious router can skip transfer of royalties and protocol fee"
    WIKI_DESCRIPTION = "## Security Advisory\n\n## Severity: Medium Risk\n\n### Context\n- **File**: LSSVMPairERC20.sol\n- **Lines**: L59-L91\n\n### Description\nA malicious router, if accidentally or intentionally whitelisted by the protocol, may implement `pair-TransferERC20From()` functions which do not actually transfer the num"
    WIKI_EXPLOIT_SCENARIO = "A malicious router can skip transfer of royalties and protocol fee"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(pairTransferERC20From|routerStatus|royalt|protocolFee)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches_regex': '(?i)^_?(pullTokenInputAndPayProtocolFee|validateTokenInput)$'}, {'function.body_contains_regex': '(?i)pairTransferERC20From\\s*\\('}, {'function.body_contains_regex': '(?i)(routerStatus|factory\\(\\)\\.routerStatus|royalt|protocolFee)'}, {'function.body_not_contains_regex': '(?i)(balanceBefore|balanceAfter|actualReceived|receivedAmount|amountReceived|postBalance|preBalance|balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)\\s*-\\s*balanceBefore)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — a-malicious-router-can-skip-transfer-of-royalties-and-protocol-f: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
