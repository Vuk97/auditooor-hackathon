"""
glider-nft-minting-allows-arbitrary-user-string-input-for — generated from reference/patterns.dsl/glider-nft-minting-allows-arbitrary-user-string-input-for.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-nft-minting-allows-arbitrary-user-string-input-for.yaml
Source: hexens-glider/nft-minting-allows-arbitrary-user-string-input-for
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderNftMintingAllowsArbitraryUserStringInputFor(AbstractDetector):
    ARGUMENT = "glider-nft-minting-allows-arbitrary-user-string-input-for"
    HELP = "NFT minting allow user provided URIs thus allowing both JSON injection and NFT impersonation"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-nft-minting-allows-arbitrary-user-string-input-for.yaml"
    WIKI_TITLE = "NFT minting allow user provided URIs thus allowing both JSON injection and NFT impersonation"
    WIKI_DESCRIPTION = "According to the ERC721 standard, each NFT should have a tokenURI which contains details regarding the NFTs such as it's attributes and image link. Upon minting, allowing the user to provide the whole tokenURI or a part of it introduces a number of risks (10 listed in [1]), this includes JSON injection [1](to target NFT sites such as OpenSea) and NFT spoofing [1]. This attack is trivial to do when"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query nft-minting-allows-arbitrary-user-string-input-for. Tags: ERC721, NFT."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ERC721|ERC1155|IERC721|IERC1155|_setTokenURI|tokenURI|TokenURI)'}, {'function.has_param_of_type': 'string'}, {'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.is_constructor': False}, {'function.name_matches': '(?i)^(mint|mintTo|mintWithURI|safeMint|safeMintTo|publicMint|premint|lazyMint)$'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_contains_regex': '(_setTokenURI|setTokenURI|tokenURIs\\s*\\[|_tokenURIs\\s*\\[|baseURI\\s*=|uri\\s*=)'}, {'function.not_source_matches_regex': '(onlyOwner|onlyRole|onlyMinter|MINTER_ROLE|keccak256\\s*\\(\\s*(abi\\.encodePacked\\s*\\(\\s*)?\\w*uri|validateURI|sanitizeURI|MerkleProof\\.verify)'}]

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
                info = [f, f" — glider-nft-minting-allows-arbitrary-user-string-input-for: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
