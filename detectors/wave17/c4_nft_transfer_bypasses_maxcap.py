"""
c4-nft-transfer-bypasses-maxcap — generated from reference/patterns.dsl/c4-nft-transfer-bypasses-maxcap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-nft-transfer-bypasses-maxcap.yaml
Source: code4arena/slice_aa-vultisig
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4NftTransferBypassesMaxcap(AbstractDetector):
    ARGUMENT = "c4-nft-transfer-bypasses-maxcap"
    HELP = "Per-user NFT cap enforced only on mint path; transfer/_update override does not re-check. Secondary-market buyers bypass the cap by purchasing from capped wallets."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-nft-transfer-bypasses-maxcap.yaml"
    WIKI_TITLE = "Per-user NFT cap bypassed via transfer"
    WIKI_DESCRIPTION = "Mint path enforces `mintedPerUser[msg.sender] < MAX_PER_USER`. `_update`/`_transfer` does not re-check, so a capped user can hold below the cap while a separate uncapped recipient stays under only by chance. Whales bypass the cap by buying from many wallets."
    WIKI_EXPLOIT_SCENARIO = "Collection caps 3 NFTs per user. Attacker mints 3 per wallet across 100 wallets then transfers all to a single sink. Sink holds 300. The cap was meaningless."
    WIKI_RECOMMENDATION = "Enforce `_checkCap(to)` in `_update` (OpenZeppelin ERC721 v5) or `_beforeTokenTransfer` so every transfer respects the cap."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'maxCapPerUser|maxPerWallet|MAX_PER_USER|mintedPerUser'}, {'contract.has_function_body_matching': 'require\\s*\\([^)]*mintedPerUser[^)]*<\\s*maxCapPerUser|require\\s*\\([^)]*maxPerWallet'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?(beforeTokenTransfer|_update|_afterTokenTransfer|_transfer|transferFrom|safeTransferFrom))$'}, {'function.body_not_contains_regex': 'maxCapPerUser|maxPerWallet|MAX_PER_USER|mintedPerUser|_checkCap'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-nft-transfer-bypasses-maxcap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
