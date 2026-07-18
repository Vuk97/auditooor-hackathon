"""
position-nft-zero-id-returns-unassigned-slot — generated from reference/patterns.dsl/position-nft-zero-id-returns-unassigned-slot.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py position-nft-zero-id-returns-unassigned-slot.yaml
Source: auditooor-R75-c4-lending-wise-lending-170
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PositionNftZeroIdReturnsUnassignedSlot(AbstractDetector):
    ARGUMENT = "position-nft-zero-id-returns-unassigned-slot"
    HELP = "ID-0 default in a user→id mapping is accepted as a valid owned id, letting any caller supply keyId=0 to pass ownership checks and claim unreserved NFTs."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/position-nft-zero-id-returns-unassigned-slot.yaml"
    WIKI_TITLE = "keyId == 0 bypass on position-NFT ownership check"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: in a mapping `reservedKeys[user] => uint256`, an address that never reserved a key returns 0. When handlers use `if (reservedKeys[msg.sender] == _keyId)` as an ownership proof and `_keyId = 0` is also the sentinel for 'no reservation', ANY caller can pass `_keyId = 0` to satisfy the check. The handler then proceeds to process `availableNFTs[0]` — which stores"
    WIKI_EXPLOIT_SCENARIO = "availableNFTs[0] holds NFT #42 (Alice's funded power-farm position). Attacker calls `exitFarm(_keyId=0, ...)`. Inside: `onlyKeyOwner(0)` modifier passes because attacker has no key. Handler computes `wiseLendingNFT = farmingKeys[0]` = 42, calls `_closingPosition(..., 42, ...)`, unwinds Alice's leveraged position, and the resulting collateral/proceeds land with msg.sender == attacker. Alice's funds"
    WIKI_RECOMMENDATION = "Reject `_keyId == 0` at function entry: `if (_keyId == 0) revert InvalidKeyId();`. Additionally, require positive reservation: `require(reservedKeys[msg.sender] != 0 && reservedKeys[msg.sender] == _keyId)`. Or encode ownership in a separate `keyOwner[tokenId]` mapping that cannot default to the atta"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(farmingKeys|reservedKeys|availableNFTs|positionKeys)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(exitFarm|claimNFT|claimKey|assignPosition|_getWiseLendingNFT|_getPositionNFT|enterFarm|redeemKey)'}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '(?i)reservedKeys\\s*\\[\\s*msg\\.sender\\s*\\]\\s*==\\s*_?\\w+|availableNFTs\\s*\\[\\s*[^\\]]*\\]'}, {'function.body_not_contains_regex': '(?i)(_?keyId\\s*(==|!=)\\s*0|_?keyId\\s*>\\s*0|require\\s*\\(\\s*_?keyId\\s*!=\\s*0|if\\s*\\(\\s*_?keyId\\s*==\\s*0\\s*\\)\\s*revert)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — position-nft-zero-id-returns-unassigned-slot: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
