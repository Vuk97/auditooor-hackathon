"""
liquidation-creates-position-for-sender-hits-cap — generated from reference/patterns.dsl/liquidation-creates-position-for-sender-hits-cap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-creates-position-for-sender-hits-cap.yaml
Source: auditooor-R75-c4-lending-wise-lending-250
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationCreatesPositionForSenderHitsCap(AbstractDetector):
    ARGUMENT = "liquidation-creates-position-for-sender-hits-cap"
    HELP = "liquidate() credits payment to an arbitrary liquidator NFT/position without checking caller owns it. Combined with a hard cap on positions per user, a borrower can grief by pre-filling target liquidator addresses with bogus positions."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-creates-position-for-sender-hits-cap.yaml"
    WIKI_TITLE = "Liquidation can be blocked by pre-filling liquidator's position slots"
    WIKI_DESCRIPTION = "When a lending protocol (a) lets callers specify the `nftIdLiquidator` that receives the reward, (b) creates a new position entry for the liquidator when the pool lacks liquid assets for the bounty, and (c) enforces a per-user cap on position count — a malicious borrower can DoS liquidations targeted at them by filling the liquidator slot first. The borrower front-runs real liquidators by invoking"
    WIKI_EXPLOIT_SCENARIO = "Cap is 8. Alice is about to be liquidated but wants to protect an accomplice liquidator Bob. Alice (via a sybil address) calls `liquidate(someOtherPosition, nftIdLiquidator = bobsNft, shareAmount=1)` eight times, creating 8 tiny collateral positions under bobsNft. When Honest-Liquidator calls `liquidate(Alice, bobsNft)`, the share transfer tries to add a 9th position → TooManyTokens revert. Alice "
    WIKI_RECOMMENDATION = "Require `msg.sender` owns `nftIdLiquidator` (or is approved operator). Prefer paying the liquidator in the underlying — not in shares that require a position slot. If shares must be minted, allocate to a mutable caller-owned ephemeral account (EIP-1167 clone per liquidation) that is guaranteed empty"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(liquidatePartial|liquidationShare|userTokenData|MAX_TOKENS)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(liquidate|liquidatePartial|_?coreLiquidation|_?doLiquidation)'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '(?i)(createPosition|_addToken|_addPosition|userTokenData\\s*\\[\\s*(msg\\.sender|caller|liquidator|_nftIdLiquidator)\\s*\\])'}, {'function.body_not_contains_regex': '(?i)(onlyOwnerOfPosition|require\\s*\\(\\s*ownerOf\\s*\\(\\s*_?\\w*nftIdLiquidator.*?\\)\\s*==\\s*msg\\.sender|require\\s*\\(\\s*isApprovedOrOwner|msg\\.sender\\s*==\\s*_liquidator)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-creates-position-for-sender-hits-cap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
