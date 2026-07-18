"""
permit2-signature-transfer-allowance-race-with-owner-update — generated from reference/patterns.dsl/permit2-signature-transfer-allowance-race-with-owner-update.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permit2-signature-transfer-allowance-race-with-owner-update.yaml
Source: auditooor-R75-consensys-permit2-integrator-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Permit2SignatureTransferAllowanceRaceWithOwnerUpdate(AbstractDetector):
    ARGUMENT = "permit2-signature-transfer-allowance-race-with-owner-update"
    HELP = "Permit2 integrator sets `requestedAmount` from a live balanceOf/allowance read rather than from the signed permit struct. An attacker who causes the user's balance/allowance to increase between signing and submission can extract the delta via signature replay of stale permit."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permit2-signature-transfer-allowance-race-with-owner-update.yaml"
    WIKI_TITLE = "Permit2 integrator reads live balance for requestedAmount, enabling sandwich-style over-transfer"
    WIKI_DESCRIPTION = "The contract builds a `PermitTransferFrom` struct using the user's signed nonce + deadline, but sets the actual `requestedAmount` from `token.balanceOf(user)` or `token.allowance(user, permit2)` at execution time. Permit2 enforces that requested <= signed.amount, so this is only safe if the signed amount is tight. In practice integrators sign for type(uint256).max to support any future balance, th"
    WIKI_EXPLOIT_SCENARIO = "User signs a permit for token X amount=type(uint256).max, nonce=42, deadline=tomorrow — intending to spend 100 X on swap. Mempool observes the signed permit. Before the swap tx lands, the user receives 5000 X from a separate airdrop. An MEV bot front-runs the swap tx with a call to the integrator's entry point that pulls `balanceOf(user) = 5100` via Permit2 and sweeps it into a bot-controlled sink"
    WIKI_RECOMMENDATION = "Always pass the user-signed amount as `requestedAmount` (or a bounded fraction of it). If a variable amount is required per-transfer, require the user to sign a fresh EIP-712 message that binds the *specific* amount and context for this call. Do not couple Permit2 pulls to live balance reads. Minimi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'permitTransferFrom|permitWitnessTransferFrom'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'permit2\\.(permitTransferFrom|permitWitnessTransferFrom)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*(msg\\.sender|owner)\\s*\\)|allowance\\s*\\('}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'requestedAmount\\s*=|amount\\s*=.*balanceOf|amount\\s*=.*allowance'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permit2-signature-transfer-allowance-race-with-owner-update: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
