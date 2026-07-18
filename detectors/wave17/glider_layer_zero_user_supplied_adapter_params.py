"""
glider-layer-zero-user-supplied-adapter-params — generated from reference/patterns.dsl/glider-layer-zero-user-supplied-adapter-params.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-layer-zero-user-supplied-adapter-params.yaml
Source: glider/layer-zero-lz-send-uses-user-supplied-adpapter-par
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderLayerZeroUserSuppliedAdapterParams(AbstractDetector):
    ARGUMENT = "glider-layer-zero-user-supplied-adapter-params"
    HELP = "LayerZero `send`/`lzSend` forwards user-supplied `adapterParams` without gas-limit validation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-layer-zero-user-supplied-adapter-params.yaml"
    WIKI_TITLE = "LayerZero adapterParams forwarded unvalidated"
    WIKI_DESCRIPTION = "LayerZero's `adapterParams` encode destination gas and native airdrop. When a wrapper passes caller-supplied bytes through, the caller controls delivery gas (can under-fund so destination reverts) and airdrop (can drain stored msg.value)."
    WIKI_EXPLOIT_SCENARIO = "Cross-chain vault forwards `adapterParams` from `bridge(bytes calldata params)` directly to `endpoint.send`. Caller encodes `(version=2, gasLimit=21000, airdrop=0.5 ether, to=attacker)`. The oracle/relayer delivers with 21000 gas, destination lzReceive reverts (out-of-gas, state never updated) while attacker collects the 0.5 ETH airdrop."
    WIKI_RECOMMENDATION = "Strip or validate `adapterParams` on the bridge entrypoint. Use `LzAppUpgradeable._checkAdapterParams` or enforce a protocol-wide minimum gas limit per destination chain."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ILayerZeroEndpoint|lzSend|_lzSend|ILzApp|LZEndpoint'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.send\\s*\\([^)]*adapterParams|_lzSend\\s*\\([^)]*adapterParams|\\.lzSend\\s*\\([^)]*adapterParams'}, {'function.has_param_of_type': 'bytes'}, {'function.body_not_contains_regex': '_checkAdapterParams|_checkGasLimit|require\\s*\\(\\s*adapterParams\\.length'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-layer-zero-user-supplied-adapter-params: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
