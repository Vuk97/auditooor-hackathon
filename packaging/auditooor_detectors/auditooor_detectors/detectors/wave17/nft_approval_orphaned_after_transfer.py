"""
nft-approval-orphaned-after-transfer — generated from reference/patterns.dsl/nft-approval-orphaned-after-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nft-approval-orphaned-after-transfer.yaml
Source: solodit-cluster-C0278
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NftApprovalOrphanedAfterTransfer(AbstractDetector):
    ARGUMENT = "nft-approval-orphaned-after-transfer"
    HELP = "Custom NFT transfer rotates ownership but never clears the per-token approval. Stale approval from previous owner survives and is usable by the approved operator to steal or burn the NFT."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nft-approval-orphaned-after-transfer.yaml"
    WIKI_TITLE = "NFT approval orphaned after transfer: stale per-token approval enables theft/burn"
    WIKI_DESCRIPTION = "ERC721 and ERC721-like contracts maintain a per-token approval (tokenApprovals / _tokenApprovals / getApproved). Custom transfer implementations that rotate ownership without also clearing or reassigning that approval leave the previous owner's approved operator able to call transferFrom / burn on the token after the ownership change. This violates the implicit ERC721 invariant that approval is sc"
    WIKI_EXPLOIT_SCENARIO = "1) Alice owns token #42 and approves operator Mallory. 2) Alice transfers #42 to Bob via the vulnerable transferFrom — ownership rotates but tokenApprovals[42] is still Mallory. 3) Mallory calls transferFrom(Bob, Mallory, 42) — the contract reads the stale approval, authorizes Mallory, and Bob loses the NFT. Burn variants (anyone can burn any NFT): Mallory calls burn(42) using the stale approval a"
    WIKI_RECOMMENDATION = "Inside every custom transfer path, clear the per-token approval as part of the ownership rotation: `delete _tokenApprovals[tokenId]` or `_approve(address(0), tokenId, owner)`. OZ's ERC721._transfer already does this — prefer inheriting it over re-implementing transfer logic. Add an invariant test: `"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'approvals|tokenApprovals|_approvals|_tokenApprovals|getApproved'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'transfer|_transfer|safeTransfer|transferFrom|_transferFrom'}, {'function.writes_storage_matching': 'owner|_owners|ownerOf'}, {'function.body_not_contains_regex': 'approvals\\[.*\\]\\s*=\\s*address\\(0\\)|delete\\s+.*approvals\\[|_approve\\s*\\(\\s*address\\(0\\)'}]

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
                info = [f, f" — nft-approval-orphaned-after-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
