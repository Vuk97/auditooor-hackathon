"""
a-malicious-user-can-craft-valid-calldata-to-call-packed-version — generated from reference/patterns.dsl/a-malicious-user-can-craft-valid-calldata-to-call-packed-version.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-user-can-craft-valid-calldata-to-call-packed-version.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousUserCanCraftValidCalldataToCallPackedVersion(AbstractDetector):
    ARGUMENT = "a-malicious-user-can-craft-valid-calldata-to-call-packed-version"
    HELP = "A malicious user can craft valid calldata to call 'packed' version of some of liﬁ endpoints"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-user-can-craft-valid-calldata-to-call-packed-version.yaml"
    WIKI_TITLE = "A malicious user can craft valid calldata to call 'packed' version of some of liﬁ endpoints "
    WIKI_DESCRIPTION = "## Security Issue in LiFi Bridge Endpoints\n\n## Context\n(No context files were provided by the reviewer)\n\n## Description\nSome endpoints of the LiFi bridge do not conform to the shape `ILiFi.BridgeData`. In that case, it is possible to craft a calldata that decodes to the tuple `ILiFi.BridgeData` but"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #54328: ## Security Issue in LiFi Bridge Endpoints\n\n## Context\n(No context files were provided by the reviewer)\n\n## Description\nSome endpoints of the LiFi bridge do not conform to the shape `ILiFi.BridgeData`"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.has_function_matching': 'validateTxData'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches_regex': '^validateTxData$'}, {'function.body_contains_regex': '(startBridgeTokensViaHopL2NativePacked|startBridgeTokensViaHopL2NativeMin|startBridgeTokensViaCBridgeNativePacked|startBridgeTokensViaCBridgeERC20Packed|startBridgeTokensViaCBridgeERC20Min|startBridgeTokensViaCBridgeNativeMin)\\s*\\.selector'}, {'function.body_contains_regex': 'abi\\.decode\\s*\\([^;]*(ILiFi\\.)?BridgeData'}, {'function.body_not_contains_regex': '(_rejectPackedEndpoint|_isPackedEndpoint|UnsupportedPackedEndpoint|PackedEndpointNotSupported|InvalidPackedSelector)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-malicious-user-can-craft-valid-calldata-to-call-packed-version: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
