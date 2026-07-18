"""
pause-state-not-propagated-to-sibling-contracts — generated from reference/patterns.dsl/pause-state-not-propagated-to-sibling-contracts.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pause-state-not-propagated-to-sibling-contracts.yaml
Source: cantina/polymarket-182
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PauseStateNotPropagatedToSiblingContracts(AbstractDetector):
    ARGUMENT = "pause-state-not-propagated-to-sibling-contracts"
    HELP = "Sibling contract (Adapter / Helper / CTF / NegRisk / Operator) exposes a position- or token-mutating external function that performs token motion but never reads the companion exchange's pause flag and carries no pause modifier of its own. Emergency pause on the exchange does not propagate; the sibl"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pause-state-not-propagated-to-sibling-contracts.yaml"
    WIKI_TITLE = "Cross-contract pause-state desync (sibling adapter ignores exchange pause)"
    WIKI_DESCRIPTION = "Multi-contract protocols often place the emergency-pause lever on a single hub (Exchange / Router) while sibling contracts (collateral adapters, position helpers, NegRisk adapters) expose their own externally-callable position ops. When the hub is paused, the broken security guarantee is *'an emergency pause halts position creation / redemption across the protocol'*. If the sibling never reads the"
    WIKI_EXPLOIT_SCENARIO = "Admin discovers an oracle issue and calls `CTFExchange.pauseTrading()`. Order matching halts. An attacker (or an indifferent counterparty) calls `CtfCollateralAdapter.splitPosition` / `mergePositions` / `redeemPositions` directly — these adapters never consult `CTFExchange.paused()`, so positions continue to be created and redeemed against the bad oracle reads. The pause's intended circuit-breaker"
    WIKI_RECOMMENDATION = "Either (a) inherit Pausable on every sibling and gate its position-mutating externals with `whenNotPaused`, or (b) make every sibling read the hub's pause state at the top of each external (`require(!IPausable(EXCHANGE).paused(), \"PAUSED\")`). Document the pause-coupling registry so future siblings"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Adapter|Collateral|Hook|Helper|Sibling|CTF|NegRisk|Operator|Clearing)'}, {'contract.not_source_matches_regex': '(?i)(Pausable|whenNotPaused|onlyWhenNotPaused)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(redeemPositions|splitPosition|mergePositions|convertPositions|redeem|unwrap|mint|burn|transfer|execute|settle)'}, {'function.has_high_level_call_named': '(?i)^(transfer|transferFrom|safeTransfer|safeTransferFrom|mint|burn|deposit|withdraw|splitPosition|mergePositions|redeemPositions|convertPositions)$'}, {'function.not_body_contains_regex': '(?i)(isPaused|\\.paused\\s*\\(\\s*\\)|require\\s*\\(\\s*!\\s*paused\\s*\\)|whenNotPaused|_checkPause|onlyWhenActive|exchange\\.paused)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pause-state-not-propagated-to-sibling-contracts: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
