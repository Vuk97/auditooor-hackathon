"""
dh-nft-unstake-safetransfer-before-clear — generated from reference/patterns.dsl/dh-nft-unstake-safetransfer-before-clear.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-nft-unstake-safetransfer-before-clear.yaml
Source: defihacklabs-2024-01/NBLGAME
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhNftUnstakeSafetransferBeforeClear(AbstractDetector):
    ARGUMENT = "dh-nft-unstake-safetransfer-before-clear"
    HELP = "NFT staking pool returns the staked NFT via ERC721 safeTransferFrom before clearing the user's stake slot, enabling reentrancy through onERC721Received to double-claim rewards or re-withdraw."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-nft-unstake-safetransfer-before-clear.yaml"
    WIKI_TITLE = "NFT stake withdrawal: safeTransferFrom fires before state clear"
    WIKI_DESCRIPTION = "Checks-Effects-Interactions violation on an NFT staking / game contract. `withdrawNft(slot)` hands the NFT back to `msg.sender` via `safeTransferFrom`, which invokes `onERC721Received` on the (contract) caller before the deposit bookkeeping (owner / index / active-bonus) is zeroed. The reentrant callback re-enters reward-claim or repeated-withdraw paths that still read the stake as active."
    WIKI_EXPLOIT_SCENARIO = "NBLGAME (Jan 2024, $180K on Optimism): flash-loan funds, deposit NFT + NBL into slot 0, then call `withdrawNft(0)`. `safeTransferFrom` triggers `onERC721Received`; inside the callback the attacker calls `depositNbl(0, flashBalance)` again — the slot is still marked active so rewards are paid out a second time against the same NFT weight. Repeat, swap NBL→USDT/WETH, repay flash loan."
    WIKI_RECOMMENDATION = "Apply `nonReentrant` to the withdrawal path, OR clear (`delete`) the stake slot BEFORE the `safeTransferFrom` call, OR switch to raw `transferFrom` if you cannot accommodate a callback. If the NFT must be refunded to a possibly-contract caller, the slot MUST be fully zero-stated before the transfer."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(NftStaking|NFTStaking|NFTPool|StakingPool|StakingRewards|Game|Vault|Farm|MasterChef|RewardPool|onERC721Received|ERC721Holder|IERC721Receiver)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdrawNft|unstakeNft|withdrawNFT|unstakeNFT|withdraw|unstake|exit|claim|withdrawStake|unstakeToken|exitStake)\\w*$'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*,\\s*msg\\.sender'}, {'function.body_not_contains_regex': 'nonReentrant|ReentrancyGuard|delete\\s+\\w+\\[[^\\]]+\\]\\s*;\\s*(?:[^;]{0,120})?safeTransferFrom|_locked\\s*=\\s*true'}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(ERC721Holder|onERC721Received\\s*\\(|view\\s+returns|pure\\s+returns|\\.transferFrom\\s*\\(|delete\\s+stakes\\s*\\[|stake\\s*=\\s*0\\s*;[^;]*safeTransferFrom)'}]

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
                info = [f, f" — dh-nft-unstake-safetransfer-before-clear: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
