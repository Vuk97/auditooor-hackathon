"""
onerc721received-reenters-transform-flag — generated from reference/patterns.dsl/onerc721received-reenters-transform-flag.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py onerc721received-reenters-transform-flag.yaml
Source: auditooor-R75-c4-yield-2024-03-revert-lend-323
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Onerc721receivedReentersTransformFlag(AbstractDetector):
    ARGUMENT = "onerc721received-reenters-transform-flag"
    HELP = "onERC721Received writes sensitive storage (loans/collateral/config) while flipping transform flag — any re-entering NFT transfer can manipulate positions."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/onerc721received-reenters-transform-flag.yaml"
    WIKI_TITLE = "onERC721Received reentrancy re-tags collateral to attacker-controlled NFT during transform()"
    WIKI_DESCRIPTION = "Vaults that accept Uniswap v3 (or other ERC721) positions as collateral often implement a transform() flow: lock the old NFT, let the user run arbitrary mutations, and accept a new NFT back through onERC721Received to replace the old collateral. If the callback trusts the `transformedTokenId` storage flag without verifying that the incoming NFT came from the expected Position Manager (or matches e"
    WIKI_EXPLOIT_SCENARIO = "Revert V3Vault.onERC721Received: during transform, user supplies a malicious ERC721 that, on `safeTransferFrom`, enters back into transform() and rewrites collateralTokenConfigs or copies debtShares onto a fresh NFT. Subsequent liquidations misroute collateral to the attacker's position."
    WIKI_RECOMMENDATION = "Restrict onERC721Received to calls originating from the real Uniswap Nonfungible Position Manager (`msg.sender == expectedPM`). Disable all re-entry into transform() and any collateral-config writes while `transformedTokenId != 0`. Validate that the new NFT's (token0, token1, fee, owner history) mat"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^onERC721Received$'}, {'function.body_contains_regex': '(?i)(transformedTokenId|transformMode|_inTransform|reentrancyFlag)'}, {'function.writes_storage_matching': '(?i)(loans|tokenOwner|collateralTokenConfig|debtShares)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — onerc721received-reenters-transform-flag: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
