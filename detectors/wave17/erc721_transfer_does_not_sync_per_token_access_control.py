"""
erc721-transfer-does-not-sync-per-token-access-control — generated from reference/patterns.dsl/erc721-transfer-does-not-sync-per-token-access-control.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc721-transfer-does-not-sync-per-token-access-control.yaml
Source: auditooor-R75-nethermind-uspd-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc721TransferDoesNotSyncPerTokenAccessControl(AbstractDetector):
    ARGUMENT = "erc721-transfer-does-not-sync-per-token-access-control"
    HELP = "An ERC-721 token that grants a role (Manager, Owner, Executor) to the minter in initialize() but does NOT revoke/transfer that role inside _update/_beforeTokenTransfer lets the original minter retain privileged access even after selling/transferring the NFT. Secondary-market buyers get the NFT witho"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc721-transfer-does-not-sync-per-token-access-control.yaml"
    WIKI_TITLE = "ERC-721 transfer hook does not revoke/grant per-token role — role diverges from ownership"
    WIKI_DESCRIPTION = "Protocols that bundle capabilities with an NFT (e.g., a stabilizer NFT that grants the holder the right to withdraw excess collateral via a role check) commonly grant the role at mint() but forget to update the role in _update/_beforeTokenTransfer. After the NFT is transferred on secondary markets, ownerOf(tokenId) returns the new owner, but the role is still held by the minter. Downstream role-ga"
    WIKI_EXPLOIT_SCENARIO = "Alice mints StabilizerNFT #7 — the initialize() grants her EXCESSCOLLATERALMANAGER_ROLE on the associated PositionEscrow. Alice sells NFT #7 to Bob on OpenSea for 10 ETH. Bob owns the NFT but cannot call removeExcessCollateral — Alice still can. Alice calls removeExcessCollateral and drains the escrow, then walks away with the sale proceeds plus the escrow balance."
    WIKI_RECOMMENDATION = "Override _update (OZ 5.x) or _beforeTokenTransfer (4.x) to (a) revoke role from `from` and (b) grant role to `to` for the specific escrow/resource. Or redesign so the role check reads `ownerOf(tokenId) == msg.sender` dynamically instead of using OZ AccessControl for per-token privileges."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ERC721|NFT).*AccessControl|AccessControl.*ERC721'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(_update|_beforeTokenTransfer|_afterTokenTransfer)'}, {'function.body_not_contains_regex': '(revokeRole|_revokeRole|grantRole|_grantRole)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc721-transfer-does-not-sync-per-token-access-control: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
