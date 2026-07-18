"""
r94-loop-bridge-pause-only-tokens-not-attestation-layer — generated from reference/patterns.dsl/r94-loop-bridge-pause-only-tokens-not-attestation-layer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-bridge-pause-only-tokens-not-attestation-layer.yaml
Source: kelp-rseth-exploit-2026-04-18-banteg-postmortem
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopBridgePauseOnlyTokensNotAttestationLayer(AbstractDetector):
    ARGUMENT = "r94-loop-bridge-pause-only-tokens-not-attestation-layer"
    HELP = "r94-loop-bridge-pause-only-tokens-not-attestation-layer"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-bridge-pause-only-tokens-not-attestation-layer.yaml"
    WIKI_TITLE = "r94-loop-bridge-pause-only-tokens-not-attestation-layer"
    WIKI_DESCRIPTION = "r94-loop-bridge-pause-only-tokens-not-attestation-layer"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-bridge-pause-only-tokens-not-attestation-layer"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(Pause|Emergency|Sweep|Freeze|BridgeAdmin)', 'function.name_matches': '(?i)(pause|freeze|emergencyPause|sweep|shutdown|disableTransfers|halt)'}
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.source_matches_regex': '(paused\\s*=\\s*true|_paused\\s*=\\s*true|tokenPaused\\s*=\\s*true|transferPaused\\s*=\\s*true|sweepRecipient|blacklist\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*true|banAddress)'}, {'function.not_source_matches_regex': '(verifyPaused\\s*=\\s*true|commitPaused\\s*=\\s*true|attestationPaused\\s*=\\s*true|endpoint\\.pause\\s*\\(|pauseReceiveLibrary|lzReceivePaused\\s*=\\s*true|bridgeFullyPaused\\s*=\\s*true|emergencyCircuitBreakAttestation)'}, {'function.body_not_contains_regex': '(ILayerZeroEndpoint\\(.+\\)\\.pause|endpoint\\.setDelegate|setReceiveLibrary|ReceiveLibraryPaused)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — r94-loop-bridge-pause-only-tokens-not-attestation-layer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
