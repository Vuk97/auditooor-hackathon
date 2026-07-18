"""
erc4626-max-view-diverges-from-actual-path — generated from reference/patterns.dsl/erc4626-max-view-diverges-from-actual-path.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-max-view-diverges-from-actual-path.yaml
Source: solodit-cluster-C0245
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626MaxViewDivergesFromActualPath(AbstractDetector):
    ARGUMENT = "erc4626-max-view-diverges-from-actual-path"
    HELP = "ERC4626 maxDeposit/maxMint/maxWithdraw/maxRedeem forwards to an inner vault's max function without applying the outer vault's pause/cap/whitelist, so the quote exceeds what the actual deposit/withdraw path will accept."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-max-view-diverges-from-actual-path.yaml"
    WIKI_TITLE = "ERC4626 max-view diverges from actual deposit/withdraw path"
    WIKI_DESCRIPTION = "The vault's ERC4626 max-view functions (maxDeposit, maxMint, maxWithdraw, maxRedeem) delegate to an inner yield vault or strategy vault's own max functions. The outer vault's deposit / withdraw path, however, enforces additional constraints — a deposit cap, a pause, a whitelist, an epoch-bounded budget, or a liquidity buffer. The max-view therefore returns a number that the actual path will reject"
    WIKI_EXPLOIT_SCENARIO = "A yield aggregator pulls `maxDeposit(user)` from Vault V and receives 10,000 USDC. The aggregator builds a transaction to deposit 10,000 USDC across V. But V also enforces a per-epoch deposit cap of 5,000 USDC that its max-view does not report. The aggregator's tx reverts on the outer cap check. The user wastes gas and the aggregator's UI displays a confusing error. At scale this breaks integratio"
    WIKI_RECOMMENDATION = "Every max-view must take the MIN of (inner-vault-view, outer-contract-limits). Re-check every gate the actual path applies — pause, deposit cap, per-user cap, whitelist, liquidity buffer — and return the tightest constraint. A simple helper: `return _min(yieldVault.maxDeposit(receiver), _outerDeposi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(maxDeposit|maxMint|maxWithdraw|maxRedeem)'}, {'contract.has_function_matching': '(deposit|mint|withdraw|redeem)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(maxDeposit|maxMint|maxWithdraw|maxRedeem)$'}, {'function.state_mutability': 'view'}, {'function.body_contains_regex': '(yieldVault|underlyingVault|strategyVault|innerVault|_yieldVault|_underlyingVault)\\s*\\.\\s*(maxDeposit|maxMint|maxWithdraw|maxRedeem)'}, {'function.body_not_contains_regex': '(paused|_paused|whenNotPaused|depositCap|maxTotalAssets|totalAssetsCap|isWhitelisted|depositAllowed|Math\\.min|_min\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-max-view-diverges-from-actual-path: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
