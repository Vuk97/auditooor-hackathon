"""
hyperevm-spot-total-vs-hold-mismatch — generated from reference/patterns.dsl/hyperevm-spot-total-vs-hold-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-spot-total-vs-hold-mismatch.yaml
Source: monetrix-c4-2026-04-W03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmSpotTotalVsHoldMismatch(AbstractDetector):
    ARGUMENT = "hyperevm-spot-total-vs-hold-mismatch"
    HELP = "HyperCore spotBalance precompile (0x801) returns (total, hold, entryNtl). Movable balance is `total - hold`; `hold` is locked in open spot orders. A pre-bridge / pre-send guard that reads `.total` without subtracting `hold` accepts amounts that L1 SEND_ASSET / SPOT_SEND will silently drop or partial"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-spot-total-vs-hold-mismatch.yaml"
    WIKI_TITLE = "HyperCore spotBalance.total used for movable-balance check (hold-aware)"
    WIKI_DESCRIPTION = "HyperCore precompile 0x801 (SpotBalance) returns three packed uint64s: `total` (gross spot balance), `hold` (locked in open spot orders), and `entryNtl` (entry notional). `total` is reported INCLUSIVE of `hold` — the L1 spot accounting model parks balance into the order book without removing it from `total`. So the actual MOVABLE balance — what SEND_ASSET, SPOT_SEND, or any outbound bridge primiti"
    WIKI_EXPLOIT_SCENARIO = "Vault has 100 USDC L1 spot — `total=100, hold=70` (70 sitting in a resting buy on a HIP-1 token). Operator calls `bridgePrincipalFromL1(80)`. Pre-flight check reads `spotBalance(...).total = 100`, sees `100 >= 80`, passes. CoreWriter SEND_ASSET fires for 80 USDC. L1 spot can only release `total - hold = 30` USDC. Result, depending on chain semantics: (a) the SEND_ASSET silently no-ops (most common"
    WIKI_RECOMMENDATION = "Always subtract `hold` from `total` before any movable-balance comparison: `uint64 movable = bal.total >= bal.hold ? bal.total - bal.hold : 0;`. Better, expose a `spotMovableUsdc(account)` helper in the PrecompileReader library that returns `total - hold` (clamped) directly, and audit all pre-bridge"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'spotBalance|SpotBalance|0x0?(?:000000000000000000000000000000000000)?0?801|PRECOMPILE_SPOT_BALANCE'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'spotBalance\\s*\\(|SpotBalance\\s+memory|PRECOMPILE_SPOT_BALANCE\\.staticcall|0x0000000000000000000000000000000000000801'}, {'function.body_contains_regex': '\\.total\\s*[\\)\\,>]|\\.total\\s*[\\+\\-\\>=<]|=\\s*[^=]*\\.total\\b|\\(\\s*uint64\\s+total\\s*,'}, {'function.body_contains_regex': 'sendBridge|sendSpotSend|sendRawAction|SEND_ASSET|SPOT_SEND|bridgeToL1|sendBridgeToL1|sendVaultWithdraw|emergencyBridge'}, {'function.body_not_contains_regex': '\\.total\\s*-\\s*[a-zA-Z_][a-zA-Z0-9_]*\\.?hold|total\\s*-\\s*hold|movable|freeBalance|availableSpot|spotAvailable|netSpot|usableSpot|hold\\s*<=?\\s*\\.?total\\s*-'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hyperevm-spot-total-vs-hold-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
