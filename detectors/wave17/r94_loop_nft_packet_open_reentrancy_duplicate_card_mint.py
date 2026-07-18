"""
r94-loop-nft-packet-open-reentrancy-duplicate-card-mint — generated from reference/patterns.dsl/r94-loop-nft-packet-open-reentrancy-duplicate-card-mint.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-nft-packet-open-reentrancy-duplicate-card-mint.yaml
Source: solodit-62592-pashov-ripit-cardallocationpool
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopNftPacketOpenReentrancyDuplicateCardMint(AbstractDetector):
    ARGUMENT = "r94-loop-nft-packet-open-reentrancy-duplicate-card-mint"
    HELP = "r94-loop-nft-packet-open-reentrancy-duplicate-card-mint"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-nft-packet-open-reentrancy-duplicate-card-mint.yaml"
    WIKI_TITLE = "r94-loop-nft-packet-open-reentrancy-duplicate-card-mint"
    WIKI_DESCRIPTION = "r94-loop-nft-packet-open-reentrancy-duplicate-card-mint"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-nft-packet-open-reentrancy-duplicate-card-mint"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Packet|CardAllocationPool|Booster|Pack|RipIt)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(openPacket|authorizedOpenPacket|openBooster|openPack|redeemPacket|revealPack|claimPackRewards)'}, {'function.source_matches_regex': '((_safeMint|safeMint|_mint|safeTransferFrom)\\s*\\([\\s\\S]{0,200}?\\)\\s*;[\\s\\S]{0,300}?(packet\\.opened\\s*=\\s*true|savePacket|commitBurn|burnPacket|_burn|isOpen\\s*=\\s*true))'}, {'function.not_source_matches_regex': '(nonReentrant|reentrancyGuard|_status\\s*=\\s*ENTERED|mutex|(packet\\.opened\\s*=\\s*true|commitBurn|_burn|burnPacket)[\\s\\S]{0,200}?(safeMint|_safeMint|safeTransferFrom))'}]

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
                info = [f, f" — r94-loop-nft-packet-open-reentrancy-duplicate-card-mint: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
