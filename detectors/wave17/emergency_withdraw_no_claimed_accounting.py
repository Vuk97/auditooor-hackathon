"""
emergency-withdraw-no-claimed-accounting — generated from reference/patterns.dsl/emergency-withdraw-no-claimed-accounting.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py emergency-withdraw-no-claimed-accounting.yaml
Source: solodit/pashov/nume-H01-31635
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EmergencyWithdrawNoClaimedAccounting(AbstractDetector):
    ARGUMENT = "emergency-withdraw-no-claimed-accounting"
    HELP = "Emergency-mode withdrawal validates the user's claimed balance via signature / Merkle proof but doesn't record what was already paid out. User replays the call and repeatedly drains their snapshot balance from the shared pool."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/emergency-withdraw-no-claimed-accounting.yaml"
    WIKI_TITLE = "Exodus / emergency withdraw has no per-user claimed mapping — repeatable drain"
    WIKI_DESCRIPTION = "An L2 / sidechain / bridge escape-hatch path lets users pull their last-attested balance when the operator goes offline. The function checks the balance (signed or Merkle-proven) and forwards it to the user, but does NOT set a `withdrawn[user] = true` or `claimed[user] += amount` flag. Because the proof / signature is a snapshot of the pre-exodus state — not an IOU that decrements — the user can l"
    WIKI_EXPLOIT_SCENARIO = "User deposits 300 USDC. Sequencer halts and the contract flips `isInExodusMode = true`. User signs `(user, currBlockNumber)` and calls `withdrawExodus(args, balance=300)` — receives 300 USDC. Calls it again with the same args — receives another 300 USDC. Continues until the pool runs out. The other 1000 users who legitimately deposited cannot exit."
    WIKI_RECOMMENDATION = "Introduce `mapping(address => bool) exited;` or `mapping(address => uint256) withdrawn;`. On first call, set / increment; on subsequent calls, revert if already exited or if cumulative withdrawn would exceed the signed balance. For NFT exits, use `exitedToken[tokenId] = true`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Exodus|EmergencyWithdraw|isInExodusMode|operatorOffline|sequencerHalt|Bridge|L2Bridge|Sidechain|Rollup|ExitGame|ExitQueue|exodusMode|emergencyMode|escape|MerkleProof)'}, {'contract.has_func_matching': '(withdrawExodus|emergencyWithdraw|exitProof|claimExit|exitForce)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdrawExodus|emergencyWithdraw|exitProof|exitForce|exitClaim|claimExit|rescueUserFunds|forceExit|emergencyExit)\\w*$'}, {'function.body_contains_regex': '(pay|transfer|safeTransfer|call\\{value)\\s*\\(|PaymentUtils\\.pay'}, {'function.body_not_contains_regex': '(withdrawn|claimed|exited|paidOut)\\s*\\[\\s*msg\\.sender\\s*\\]\\s*[+-]?=|\\.used\\s*=\\s*true|used\\[.*\\]\\s*=\\s*true'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'recoverSigner|MerkleProof\\.verify|ecrecover'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(BitMaps\\.setTo|claimedBitMap|isClaimed\\s*\\(|super\\.emergencyWithdraw|super\\.withdrawExodus|view\\s+returns|pure\\s+returns|exitedToken\\s*\\[\\s*tokenId|merkleRootClaimed)'}]

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
                info = [f, f" — emergency-withdraw-no-claimed-accounting: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
