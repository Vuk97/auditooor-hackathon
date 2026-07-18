"""
glider-claiming-nft-rewards-lack-ownership-validation — generated from reference/patterns.dsl/glider-claiming-nft-rewards-lack-ownership-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-claiming-nft-rewards-lack-ownership-validation.yaml
Source: hexens-glider/claiming-nft-rewards-lack-ownership-validation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderClaimingNftRewardsLackOwnershipValidation(AbstractDetector):
    ARGUMENT = "glider-claiming-nft-rewards-lack-ownership-validation"
    HELP = "claimReward does not verify token ownership"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-claiming-nft-rewards-lack-ownership-validation.yaml"
    WIKI_TITLE = "claimReward does not verify token ownership"
    WIKI_DESCRIPTION = "Detects reward-claiming functions (e.g., `claimReward`, `claim`, `claimRewards`) that accept a `tokenId` parameter but do NOT validate that `msg.sender` is the owner of that token. Missing such checks allows attackers to claim rewards for any tokenId they do not own."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query claiming-nft-rewards-lack-ownership-validation. Tags: reward, nft, access-control, tokenId, ownership."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'function.name_matches': '(claim|harvest|collect)'}, {'contract.source_matches_regex': '(RewardDistributor|NFTStaking|StakingPool|NftStaking|Rewards|claimReward|tokenId|ERC721|ERC1155|IERC721|IERC1155)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(claim|claimReward|claimRewards|claimFor|harvest|harvestRewards|collect|collectRewards|claimTokenRewards|claimAll)\\w*$'}, {'function.body_contains_regex': '(?:uint256|uint)\\s+tokenId|tokenId\\s*,|tokenIds\\[|rewards\\[\\s*tokenId'}, {'function.body_contains_regex': '(?i)(rewards\\[\\s*tokenId|pendingRewards\\[\\s*tokenId|userReward|_mint\\s*\\(|payReward|transfer\\s*\\(|safeTransfer\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(ownerOf\\s*\\(\\s*tokenId\\s*\\)\\s*==\\s*msg\\.sender|require\\s*\\(\\s*msg\\.sender\\s*==\\s*ownerOf|_isApprovedOrOwner\\s*\\(\\s*msg\\.sender|stakers\\[\\s*tokenId\\s*\\]\\s*==\\s*msg\\.sender|depositors\\[\\s*tokenId\\s*\\]\\s*==\\s*msg\\.sender|owners\\[\\s*tokenId\\s*\\]\\s*==\\s*msg\\.sender)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|internal\\s+view|internal\\s+pure|onlyOwnerOf|onlyTokenOwner|onlyStaker|modifier\\s+onlyOwnerOf|modifier\\s+tokenOwner|claimFor\\s*\\(\\s*address\\s+user[^)]*\\)\\s*(?:external|public)\\s+onlyOwner)'}]

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
                info = [f, f" — glider-claiming-nft-rewards-lack-ownership-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
