"""
r74-input-signature-missing-tokenid-binding — generated from reference/patterns.dsl/r74-input-signature-missing-tokenid-binding.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-input-signature-missing-tokenid-binding.yaml
Source: r74b-cross-firm-cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74InputSignatureMissingTokenidBinding(AbstractDetector):
    ARGUMENT = "r74-input-signature-missing-tokenid-binding"
    HELP = "EIP-712 / bespoke signature hash does not bind the tokenId/marketId/poolId the call operates on; a signature valid for one instance replays to other instances owned by the same signer."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-input-signature-missing-tokenid-binding.yaml"
    WIKI_TITLE = "Signed digest missing instance-ID (tokenId/marketId/poolId) binding"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned veNFT-style vote path where a function accepts `tokenId`, verifies a typed-data signature, uses `ownerOf(tokenId)` to bind signer ownership, but omits `tokenId` from the encoded payload. A signature collected for one veNFT can then be replayed against another veNFT owned by the same signer. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A governance framework lets veNFT holders sign a vote off-chain. The digest is keccak256(abi.encode(VOTE_TYPEHASH, voter, proposalId, support, nonce, deadline)). It does NOT include the veNFT tokenId that the vote is cast from. A voter owns two veNFTs with different voting weights. They sign to vote YES with their smaller veNFT. The operator relays the signature — and then relays it again against "
    WIKI_RECOMMENDATION = "Include every instance discriminator in the typed-data struct: `struct Vote { uint256 tokenId; uint256 proposalId; uint8 support; uint256 nonce; uint256 deadline; }`. If nonces are per-voter, switch to per-(voter, tokenId) nonces. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owne"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?s)(EIP712|DOMAIN_SEPARATOR|_TYPEHASH).*(tokenId|marketId|poolId|gaugeId|assetId|venftId|nftId)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.has_param_name_matching': '^(tokenId|marketId|poolId|gaugeId|assetId|venftId|nftId)$'}, {'function.body_contains_regex': '_hashTypedDataV4\\s*\\(|_hashTypedData\\s*\\(|keccak256\\s*\\(\\s*abi\\.encode\\s*\\([^)]*_TYPEHASH|keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\([^)]*_TYPEHASH'}, {'function.body_contains_regex': '\\b(nonce|deadline)\\b'}, {'function.body_contains_regex': 'ownerOf\\s*\\(\\s*tokenId|positions\\s*\\[\\s*(tokenId|marketId|assetId|venftId|nftId)|markets\\s*\\[\\s*marketId|pools\\s*\\[\\s*poolId|gauges\\s*\\[\\s*gaugeId'}, {'function.has_high_level_call_named': '(?i)^(recover|_recover|tryRecover|recoverSigner|_recoverSigner|isValidSignatureNow)$'}, {'function.body_not_contains_regex': 'abi\\.encode\\s*\\([^;{}]*(tokenId|marketId|poolId|gaugeId|assetId|venftId|nftId)|abi\\.encodePacked\\s*\\([^;{}]*(tokenId|marketId|poolId|gaugeId|assetId|venftId|nftId)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-input-signature-missing-tokenid-binding: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
