"""
pashov-internal-vs-external-share-tracking-divergence — generated from reference/patterns.dsl/pashov-internal-vs-external-share-tracking-divergence.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pashov-internal-vs-external-share-tracking-divergence.yaml
Source: auditooor-R75-pashov-EulerEarn-PublicAllocator-M01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PashovInternalVsExternalShareTrackingDivergence(AbstractDetector):
    ARGUMENT = "pashov-internal-vs-external-share-tracking-divergence"
    HELP = "Allocator uses external `id.maxWithdraw(vault)` (real shares incl. donated ones) while the core vault's accounting uses `config[id].balance` (internal shares). Donations skew the two — flow caps and target allocations get computed against real shares but operations execute against internal shares, p"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pashov-internal-vs-external-share-tracking-divergence.yaml"
    WIKI_TITLE = "Public allocator reads real ERC4626 shares while core uses internal tracking (share drift on donation)"
    WIKI_DESCRIPTION = "A two-layer vault (e.g. MetaMorpho / EulerEarn + PublicAllocator) that tracks strategy balances internally (`config[id].balance`) to defend against donation attacks must enforce the same source of truth everywhere. When the helper allocator instead reads `id.maxWithdraw(address(vault))` — which returns the redeemable value of ALL shares the vault holds, including frontrun-donated strategy shares —"
    WIKI_EXPLOIT_SCENARIO = "EulerEarn/MetaMorpho-fork: Attacker front-runs a vault allocator call by minting 20 units of strategy-vault shares directly to EulerEarn (MetaMorpho's supply uses internal accounting, so the donated 20 are invisible to `config[id].balance` but real to `maxWithdraw`). The allocator requests a 30-unit reallocation from that strategy. PublicAllocator measures `maxWithdraw = 70` (50 internal + 20 dona"
    WIKI_RECOMMENDATION = "In every allocator entry point that sizes a reallocation, read the vault's internal bookkeeping, not the ERC4626 surface: either expose `function expectedSupplyAssets(IERC4626 id) external view returns (uint256)` on the core vault that returns `previewRedeem(config[id].balance)`, or have the allocat"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'EulerEarn|MetaMorpho|PublicAllocator|config\\[id\\]\\.balance|Allocator'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'reallocateTo|reallocate|rebalance|allocate|setFlowCaps'}, {'function.body_contains_regex': '\\.maxWithdraw\\s*\\(\\s*(vault|address\\(this\\)|address\\(vault\\))'}, {'function.body_not_contains_regex': 'config\\[id\\]\\.balance|expectedSupplyAssets|_expectedSupplyAssets|internalBalance|previewRedeem\\s*\\(\\s*config'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pashov-internal-vs-external-share-tracking-divergence: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
