"""
glider-lack-of-msgsender-validations-on-layer-zero-endpoi — generated from reference/patterns.dsl/glider-lack-of-msgsender-validations-on-layer-zero-endpoi.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-lack-of-msgsender-validations-on-layer-zero-endpoi.yaml
Source: hexens-glider/lack-of-msgsender-validations-on-layer-zero-endpoi
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderLackOfMsgsenderValidationsOnLayerZeroEndpoi(AbstractDetector):
    ARGUMENT = "glider-lack-of-msgsender-validations-on-layer-zero-endpoi"
    HELP = "Protocol Which Integrates LayerZero Fail to Ensure msg.sender is LzEndpoint in lzReceive/lzCompose thus Allowing Malicious Payloads to be Sent"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-lack-of-msgsender-validations-on-layer-zero-endpoi.yaml"
    WIKI_TITLE = "Protocol Which Integrates LayerZero Fail to Ensure msg.sender is LzEndpoint in lzReceive/lzCompose thus Allowing Malicious Payloads to be Se"
    WIKI_DESCRIPTION = "Failing to ensure msg.sender is the endpoint for both lzReceive and lzCompose allows malicious actors to send Malicious payloads which can allow them to steal funds or perform restricted actions. The impact varies depending on the protocol but for most protocols, this would be a critical as lzReceive/lzCompose often involve accounting. Note: This has been extended to also include Stargate's 'sgRec"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query lack-of-msgsender-validations-on-layer-zero-endpoi. Tags: LayerZero."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.is_constructor': False}, {'function.name_matches': '^(lzReceive|lzCompose|sgReceive)$'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-lack-of-msgsender-validations-on-layer-zero-endpoi: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
