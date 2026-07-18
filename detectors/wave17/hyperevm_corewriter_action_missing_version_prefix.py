"""
hyperevm-corewriter-action-missing-version-prefix — generated from reference/patterns.dsl/hyperevm-corewriter-action-missing-version-prefix.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-corewriter-action-missing-version-prefix.yaml
Source: monetrix-c4-2026-04-action-encoder
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmCorewriterActionMissingVersionPrefix(AbstractDetector):
    ARGUMENT = "hyperevm-corewriter-action-missing-version-prefix"
    HELP = "Hyperliquid CoreWriter requires every action to start with `ACTION_VERSION` (0x01), then a 3-byte action_id, then abi-encoded args. A `sendRawAction(bytes)` invocation built without the version-byte prefix is silently dropped on L1 — the EVM transaction succeeds, the L1 effect never happens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-corewriter-action-missing-version-prefix.yaml"
    WIKI_TITLE = "HyperEVM CoreWriter sendRawAction missing ACTION_VERSION prefix (silent L1 drop)"
    WIKI_DESCRIPTION = "Hyperliquid's CoreWriter precompile (0x3333333333333333333333333333333333333333) is the single write-side gateway from EVM to L1. Its public surface is `sendRawAction(bytes calldata data)` — the bytes are NOT validated by CoreWriter beyond a version-byte check, then forwarded to L1. The required wire format is `data[0] = ACTION_VERSION (currently 0x01) || data[1..3] = action_id (uint24 big-endian)"
    WIKI_EXPLOIT_SCENARIO = "Vault has an `emergencySendBridge` path that takes a pre-encoded `bytes` payload (because the standard `sendBridgeToL1` is paused). Operator pulls the encoding from a runbook that was written before `ACTION_VERSION` was introduced (or copied from an internal Hyperliquid testnet doc that omitted the version). Operator calls `coreWriter.sendRawAction(legacyEncodedBytes)` — succeeds on EVM. The vault"
    WIKI_RECOMMENDATION = "Centralize ALL CoreWriter dispatch in an `ActionEncoder` library. Every `sendX` function MUST start the bytes with the `ACTION_VERSION` constant: `bytes memory action = abi.encodePacked(HyperCoreConstants.ACTION_VERSION, ACTION_<X>, abi.encode(args));`. Forbid raw `sendRawAction(bytes)` calls outsid"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'sendRawAction|CORE_WRITER|0x3333333333333333333333333333333333333333|ICoreWriter|HyperCoreConstants|abi\\.encodePacked.*ACTION_'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'sendRawAction\\s*\\(|0x3333333333333333333333333333333333333333|CORE_WRITER\\.call|ICoreWriter\\([^)]*\\)\\.sendRawAction'}, {'function.body_contains_regex': 'abi\\.encodePacked\\s*\\(|abi\\.encode\\s*\\('}, {'function.body_not_contains_regex': 'ACTION_VERSION|VERSION_BYTE|uint8\\s*\\(\\s*1\\s*\\)\\s*,|bytes1\\s*\\(\\s*0x01\\s*\\)|0x01\\s*,\\s*ACTION_|hex"01"|encodePacked\\s*\\(\\s*uint8\\s*\\(\\s*1\\s*\\)|encodePacked\\s*\\(\\s*bytes1\\s*\\(\\s*0x01\\s*\\)|HyperCoreConstants\\.ACTION_VERSION'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hyperevm-corewriter-action-missing-version-prefix: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
