"""
r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks — generated from reference/patterns.dsl/r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks.yaml
Source: solodit-29457-c4-dopex-univ3liquidityamo
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopErc721RecoverUsesTransferNotSafetransferLocks(AbstractDetector):
    ARGUMENT = "r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks"
    HELP = "r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks.yaml"
    WIKI_TITLE = "r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks"
    WIKI_DESCRIPTION = "r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(IERC721|ERC721|UniV3LiquidityAMO|NFT|Recover|Rescue)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(recoverERC721|sweepNft|withdrawERC721|rescueNft|emergencyRecoverNft|recoverPositionNft)'}, {'function.source_matches_regex': '(nft\\.transfer\\s*\\(|erc721\\.transfer\\s*\\(|IERC721\\s*\\(\\s*\\w+\\s*\\)\\.transfer\\s*\\(|\\.transfer\\s*\\(\\s*\\w*(to|recipient|receiver)\\s*,\\s*\\w*tokenId\\s*\\))'}, {'function.not_source_matches_regex': '(safeTransferFrom)'}]

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
                info = [f, f" — r94-loop-erc721-recover-uses-transfer-not-safetransfer-locks: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
