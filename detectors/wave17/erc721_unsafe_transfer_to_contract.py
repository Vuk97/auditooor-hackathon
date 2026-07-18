"""
erc721-unsafe-transfer-to-contract — generated from reference/patterns.dsl/erc721-unsafe-transfer-to-contract.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc721-unsafe-transfer-to-contract.yaml
Source: auditooor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc721UnsafeTransferToContract(AbstractDetector):
    ARGUMENT = "erc721-unsafe-transfer-to-contract"
    HELP = "ERC721 transferFrom used to send an NFT to a potentially-contract recipient. If the recipient is a contract without onERC721Received, the NFT is irrecoverable. Use safeTransferFrom."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc721-unsafe-transfer-to-contract.yaml"
    WIKI_TITLE = "ERC721 unsafe transferFrom to contract: permanent NFT lockup risk"
    WIKI_DESCRIPTION = "ERC721 defines two ownership-rotation primitives: the raw `transferFrom` (no callback, no recipient check) and `safeTransferFrom` (invokes `onERC721Received` on contract recipients and reverts if the recipient does not implement the interface). When a contract routes NFTs to an arbitrary (potentially contract) recipient using the raw `transferFrom`, and that recipient is an EOA wrapper / multisig "
    WIKI_EXPLOIT_SCENARIO = "1) Escrow/vault/staking contract exposes a withdrawal path that sends an ERC721 to `to` via `IERC721(token).transferFrom(address(this), to, tokenId)`. 2) A user submits a contract address (e.g., a naive wallet, an out-of-date Gnosis Safe, or an intermediate proxy) as `to`. 3) The transfer succeeds silently — `transferFrom` does not check `onERC721Received` and does not revert. 4) The NFT now sits "
    WIKI_RECOMMENDATION = "Replace every `IERC721(...).transferFrom(...)` going to an untrusted or caller-controlled address with `safeTransferFrom`. The OpenZeppelin ERC721 implementation emits the `onERC721Received` callback and reverts on non-compliant recipients, which makes the lockup path impossible. If you must use the"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.body_contains_regex': 'IERC721\\s*\\(\\s*\\w+\\s*\\)\\.transferFrom\\s*\\(|IERC721\\.transferFrom|erc721\\.transferFrom|nft\\.transferFrom'}, {'function.body_not_contains_regex': 'safeTransferFrom|IERC721\\.safeTransferFrom|\\.safeTransferFrom'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc721-unsafe-transfer-to-contract: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
