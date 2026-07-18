"""
gas-estimation-cross-chain-undercount — generated from reference/patterns.dsl/gas-estimation-cross-chain-undercount.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gas-estimation-cross-chain-undercount.yaml
Source: solodit-cross-chain-standard-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GasEstimationCrossChainUndercount(AbstractDetector):
    ARGUMENT = "gas-estimation-cross-chain-undercount"
    HELP = "Cross-chain send function forwards a gas limit computed on the source chain without padding for destination-chain intrinsic / overhead costs — the message can revert on delivery and become permanently stuck."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gas-estimation-cross-chain-undercount.yaml"
    WIKI_TITLE = "Cross-chain gas undercount: destination intrinsic / overhead not accounted for"
    WIKI_DESCRIPTION = "Cross-chain messaging systems let a caller specify (or bond) the gas limit that will be supplied when the destination chain executes the delivered message. Each chain has its own intrinsic-gas model: L1 pays 21000 base + 16 per non-zero calldata byte, but L2s add rollup-specific overhead (Arbitrum's L1-cost, Optimism's rollup fee, zkSync's proof-submission overhead, Polygon zkEVM's bridge overhead"
    WIKI_EXPLOIT_SCENARIO = "A user calls `sendToL2(recipient, amount, _gasLimit)` with a `_gasLimit` that was calculated on Ethereum mainnet using `estimateGas(...)` against a local fork. The source contract forwards this raw value to the canonical L1→L2 messenger. On the destination L2 the delivered message executes `recipient.call{gas: _gasLimit}(data)` but L2 charges intrinsic 21000 + per-byte plus a chain-specific overhe"
    WIKI_RECOMMENDATION = "Never forward a caller-supplied gas limit directly. Apply a destination-chain-aware padding: `_gasLimit + INTRINSIC_GAS + calldataLen * _minGasPerByte + OVERHEAD[destChainId]`. Prefer a chain-indexed `gasBuffer` mapping that encodes the known intrinsic + rollup overhead for each supported destinatio"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'sendMessage|sendToL2|sendCrossChain|crossChainSend|_sendMessage'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'sendMessage|sendToL2|sendCrossChain|_sendMessage|createCrossChainCall'}, {'function.body_contains_regex': '_gasLimit|gasLimit\\s*:|estimateGas|gas\\s*:\\s*\\w+'}, {'function.body_not_contains_regex': 'INTRINSIC_GAS|OVERHEAD|_minGasPerByte|estimateIntrinsic|gasBuffer|OVERHEAD_GAS'}]

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
                info = [f, f" — gas-estimation-cross-chain-undercount: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
