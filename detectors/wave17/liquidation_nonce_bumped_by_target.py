"""
liquidation-nonce-bumped-by-target — generated from reference/patterns.dsl/liquidation-nonce-bumped-by-target.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-nonce-bumped-by-target.yaml
Source: solodit/sherlock/symmetrical-H7-21200
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationNonceBumpedByTarget(AbstractDetector):
    ARGUMENT = "liquidation-nonce-bumped-by-target"
    HELP = "Liquidation (or slash / force-close) requires an off-chain signature bound to a per-account nonce that the account owner can bump via trivial calls. Owner loops nonce bumps every block to perpetually block liquidation."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-nonce-bumped-by-target.yaml"
    WIKI_TITLE = "Signature nonce controlled by the liquidation target blocks liquidations"
    WIKI_DESCRIPTION = "An off-chain oracle signs `(account, nonce, upnl, timestamp)` to authenticate the liquidatable status of an account. The contract binds the hash to the account's own nonce, which the account owner can increment with any no-op action (open & cancel a dummy position, allocate & deallocate dust, rotate a self-approval). When the account becomes liquidatable, the owner monitors the mempool / submits a"
    WIKI_EXPLOIT_SCENARIO = "partyA's position deteriorates. Oracle signs `(partyA, nonce=5, upnl=-10000)`. Liquidator submits `liquidatePartyA(sig)`. partyA's bot sees the pending tx in the mempool, front-runs with `allocateFunds(1 wei)` which internally bumps `partyANonces[partyA]` to 6. Liquidator's tx reverts because the recovered signer doesn't match (hash mismatch on nonce). Oracle re-signs with nonce=6 (1 second latenc"
    WIKI_RECOMMENDATION = "Do not use a target-controlled nonce for liquidation authorization. Either (a) use a global sequencer nonce not controllable by the target, (b) sign `(account, blockNumber)` and enforce `block.number == signedBlockNumber + k` at verify time, or (c) short-circuit the nonce check during liquidation an"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(partyANonce|targetNonce|accountNonce|userNonce)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidate|liquidatePartyA|liquidatePartyB|liquidateAccount|liquidatePosition|slash|slashValidator|forceClose|forceCloseAll|kick|kickAccount|seize|seizeCollateral)$'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'verify|recover|ecrecover'}, {'function.body_contains_regex': 'abi\\.encode(Packed)?\\s*\\([^)]*nonces?\\s*\\[\\s*(partyA|target|account|user)\\s*\\]'}, {'contract.has_func_body_matching': '(nonces?|partyANonce)\\s*\\[\\s*msg\\.sender\\s*\\]\\s*(\\+\\+|\\+=\\s*1)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-nonce-bumped-by-target: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
