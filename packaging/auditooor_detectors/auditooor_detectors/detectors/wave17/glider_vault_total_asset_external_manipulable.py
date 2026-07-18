"""
glider-vault-total-asset-external-manipulable — generated from reference/patterns.dsl/glider-vault-total-asset-external-manipulable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-vault-total-asset-external-manipulable.yaml
Source: glider/vault-total-asset-rely-on-external-manipulatable
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderVaultTotalAssetExternalManipulable(AbstractDetector):
    ARGUMENT = "glider-vault-total-asset-external-manipulable"
    HELP = "ERC4626 totalAssets() reads a flash-manipulable external source (Curve virtual price, pool reserves, spot oracle). Attacker sandwich-manipulates the source to mint at bad rates."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-vault-total-asset-external-manipulable.yaml"
    WIKI_TITLE = "totalAssets() relies on externally-manipulable price"
    WIKI_DESCRIPTION = "ERC4626 vaults use totalAssets() in share-conversion math. If this number depends on a value that any block can push (AMM reserves, un-TWAP'd oracle, pool virtual price derived from reserves), flash-loan attackers distort the vault's exchange rate intra-transaction, minting or redeeming at attacker-favorable rates."
    WIKI_EXPLOIT_SCENARIO = "Vault wraps a Curve LP. `totalAssets()` returns `lpBalance * pool.get_virtual_price() / 1e18`. Attacker swaps a huge amount into the Curve pool, inflating virtual price, deposits into the vault (gets cheap shares), undoes the swap, redeems shares at the now-restored virtual price — extracting the delta."
    WIKI_RECOMMENDATION = "Use time-weighted / block-spanning aggregations for pricing: Curve's `stored_rates` + oracle snapshot, Balancer's weighted rate provider, or your own TWAP observation. Never read `get_virtual_price` in the same tx as a deposit/mint."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ERC4626|totalAssets|convertToShares)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(totalAssets|_totalAssets)$'}, {'function.state_mutability': 'view'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'getVirtualPrice\\s*\\(|get_virtual_price\\s*\\(|getReserves\\s*\\(|price_oracle\\s*\\(|latestAnswer\\s*\\(|\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*\\w*(pool|pair)\\w*\\s*\\)\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-vault-total-asset-external-manipulable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
