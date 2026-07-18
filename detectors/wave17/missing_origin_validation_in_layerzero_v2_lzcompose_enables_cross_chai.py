"""
missing-origin-validation-in-layerzero-v2-lzcompose-enables-cross-chai — generated from reference/patterns.dsl/missing-origin-validation-in-layerzero-v2-lzcompose-enables-cross-chai.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-origin-validation-in-layerzero-v2-lzcompose-enables-cross-chai.yaml
Source: Hexens Glider query missing-message-origin-validation-in-layer-zero-v2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingOriginValidationInLayerzeroV2LzcomposeEnablesCrossChai(AbstractDetector):
    ARGUMENT = "missing-origin-validation-in-layerzero-v2-lzcompose-enables-cross-chai"
    HELP = "LayerZero V2 lzCompose handler authenticates the endpoint but lacks visible origin validation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-origin-validation-in-layerzero-v2-lzcompose-enables-cross-chai.yaml"
    WIKI_TITLE = "Missing origin validation in LayerZero V2 lzCompose"
    WIKI_DESCRIPTION = "Flags lzCompose handlers that appear to trust msg.sender == endpoint as the only boundary before state/accounting changes, without a visible _from allowlist/peer check or composeFrom(_message) source-sender check."
    WIKI_EXPLOIT_SCENARIO = "An attacker-controlled OApp queues a compose message through the real endpoint. The target sees msg.sender == endpoint and credits forged message data because it never checks the delivering OFT/OApp origin."
    WIKI_RECOMMENDATION = "In lzCompose, require the endpoint caller and validate the delivering _from OFT/OApp plus the decoded source sender before mutating accounting."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\b(lzCompose|ILayerZeroComposer|OFTComposeMsgCodec|LayerZero|endpoint)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^lzCompose$'}, {'function.body_contains_regex': '\\bmsg\\.sender\\b\\s*(==|!=)\\s*(address\\s*\\(\\s*)?(endpoint|lzEndpoint|lzEndpointV2|LAYER_ZERO_ENDPOINT|LAYERZERO_ENDPOINT|LZ_ENDPOINT|LAYER_ZERO_V2_ENDPOINT)\\b'}, {'function.body_contains_regex': '\\b(balance|balances|credit|credits|deposit|deposits|mint|_mint|safeTransfer|transfer|amountLD|shares|receipt|accounting)\\b'}, {'function.body_not_contains_regex': '(_from\\s*(==|!=)\\s*(trusted|authorized|allowed|expected|remote|source|origin|peer|oft|oapp)|OFTComposeMsgCodec\\s*\\.\\s*composeFrom\\s*\\([^)]*\\)\\s*(==|!=)|composeFrom\\s*\\([^)]*\\)\\s*(==|!=))'}]

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
                info = [f, f" — missing-origin-validation-in-layerzero-v2-lzcompose-enables-cross-chai: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
