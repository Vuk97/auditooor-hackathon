"""
r94-loop-vault-share-balance-of-self-rebasing-steal — generated from reference/patterns.dsl/r94-loop-vault-share-balance-of-self-rebasing-steal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-vault-share-balance-of-self-rebasing-steal.yaml
Source: solodit-35735-c4-thorchain
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopVaultShareBalanceOfSelfRebasingSteal(AbstractDetector):
    ARGUMENT = "r94-loop-vault-share-balance-of-self-rebasing-steal"
    HELP = "r94-loop-vault-share-balance-of-self-rebasing-steal"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-vault-share-balance-of-self-rebasing-steal.yaml"
    WIKI_TITLE = "r94-loop-vault-share-balance-of-self-rebasing-steal"
    WIKI_DESCRIPTION = "r94-loop-vault-share-balance-of-self-rebasing-steal"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-vault-share-balance-of-self-rebasing-steal"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Vault|ERC4626|Pool|RebasingVault|Thorchain|StakingVault)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|mintShares|joinVault|stakeLp|withdraw|redeemShares|burnShares)'}, {'function.source_matches_regex': '(amount\\s*\\*\\s*\\w*(totalShares|total_shares|totalSupply)\\s*\\/\\s*\\w*balanceOf\\s*\\(\\s*(address\\s*\\(\\s*this\\s*\\)|this)|amount\\s*\\*\\s*\\w*(totalShares|totalSupply)\\s*\\/\\s*\\w*token\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\))'}, {'function.not_source_matches_regex': '(trackedBalance|storedBalance|internalBalance|totalAssets\\s*\\(\\s*\\)|principalTracked|underlyingTotal|snapshotAssetBalance|checkpointedBalance)'}]

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
                info = [f, f" — r94-loop-vault-share-balance-of-self-rebasing-steal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
