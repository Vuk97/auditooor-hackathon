"""
erc4626-redeem-zero-assets-burns-shares — generated from reference/patterns.dsl/erc4626-redeem-zero-assets-burns-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-redeem-zero-assets-burns-shares.yaml
Source: solodit-novel/slice_aa-glif-12
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626RedeemZeroAssetsBurnsShares(AbstractDetector):
    ARGUMENT = "erc4626-redeem-zero-assets-burns-shares"
    HELP = "ERC-4626 redeem/withdraw burns shares even when the converted assets round to zero. Caller loses shares without receiving anything; violates spec."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-redeem-zero-assets-burns-shares.yaml"
    WIKI_TITLE = "ERC-4626 redeem burns shares when assets round to zero"
    WIKI_DESCRIPTION = "ERC-4626 redeem/withdraw must NOT burn shares when the share->asset conversion yields zero assets. Implementations that unconditionally burn shares after `assets = convertToAssets(shares)` silently destroy value when small-share rounding hits zero."
    WIKI_EXPLOIT_SCENARIO = "Vault has 1e30 totalAssets across 1e36 totalShares (ratio << 1). User redeems 1 share, convertToAssets rounds down to 0 assets. The function still executes `_burn(owner, 1)` and transfers 0 assets. User permanently loses the share."
    WIKI_RECOMMENDATION = "After computing assets, `require(assets > 0, \"ZERO_ASSETS\")` (or equivalent custom-error revert) before `_burn`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ERC4626|IERC4626|totalAssets|convertToAssets'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(redeem|withdraw)$'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '_burn\\s*\\(|burn\\s*\\(\\s*(owner|msg\\.sender|shares)|\\.burn\\s*\\('}, {'function.body_contains_regex': 'convertToAssets|previewRedeem|previewWithdraw'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*assets\\s*(>|!=)\\s*0|if\\s*\\(\\s*assets\\s*==\\s*0\\s*\\)\\s*revert|ZeroAssets\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-redeem-zero-assets-burns-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
