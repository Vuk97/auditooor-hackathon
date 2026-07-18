"""
nft-minting-allow-user-provided-uris-thus-allowing-both-json-injection — generated from reference/patterns.dsl/nft-minting-allow-user-provided-uris-thus-allowing-both-json-injection.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nft-minting-allow-user-provided-uris-thus-allowing-both-json-injection.yaml
Source: hexens-glider/nft-minting-allows-arbitrary-user-string-input-for
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NftMintingAllowUserProvidedUrisThusAllowingBothJsonInjection(AbstractDetector):
    ARGUMENT = "nft-minting-allow-user-provided-uris-thus-allowing-both-json-injection"
    HELP = "NOT_SUBMIT_READY fixture-smoke only: public mint-like entrypoints that accept a raw URI string and write it into NFT metadata without a visible validation step."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nft-minting-allow-user-provided-uris-thus-allowing-both-json-injection.yaml"
    WIKI_TITLE = "NFT minting allows raw user-provided token URIs"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row is intentionally narrow: it covers public or external mint-like functions that accept a string parameter, visibly mint, and visibly store that URI-shaped input as NFT metadata without a visible validate/sanitize step in the same function body."
    WIKI_EXPLOIT_SCENARIO = "A user calls `publicMint(userProvidedUri)`. The function mints a token and immediately forwards `userProvidedUri` into `_setTokenURI` or equivalent metadata storage. Off-chain NFT renderers can then resolve attacker-chosen metadata, including spoofed or malformed JSON. This row does not claim corpus-backed exploit evidence beyond the owned fixture pair."
    WIKI_RECOMMENDATION = "Do not let arbitrary callers choose token metadata URIs directly. Mint from trusted metadata, or validate and sanitize URI inputs before writing them. Do not promote from this fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(ERC721|ERC1155|IERC721|IERC1155|tokenURI|_setTokenURI)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.is_constructor': False}, {'function.name_matches': '(?i)^(mint|mintTo|mintWithURI|safeMint|safeMintTo|publicMint|premint|lazyMint)$'}, {'function.has_param_of_type': 'string'}, {'function.body_contains_regex': '(?i)(_safeMint\\s*\\(|safeMint\\s*\\(|_mint\\s*\\()'}, {'function.body_contains_regex': '(?i)(_setTokenURI|setTokenURI|tokenURIs\\s*\\[|_tokenURIs\\s*\\[|baseURI\\s*=|uri\\s*=)'}, {'function.body_not_contains_regex': '(?i)(validateURI|sanitizeURI|MerkleProof\\.verify|keccak256\\s*\\(\\s*(abi\\.encodePacked\\s*\\(\\s*)?\\w*uri)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — nft-minting-allow-user-provided-uris-thus-allowing-both-json-injection: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
