"""
erc4626-mint-zero-shares-no-revert — generated from reference/patterns.dsl/erc4626-mint-zero-shares-no-revert.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-mint-zero-shares-no-revert.yaml
Source: auditooor-erc4626
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626MintZeroSharesNoRevert(AbstractDetector):
    ARGUMENT = "erc4626-mint-zero-shares-no-revert"
    HELP = "ERC4626 deposit/mint computes shares via previewDeposit / convertToShares but does not revert when the result rounds to zero — caller's assets are pulled into the vault while they receive zero shares, effectively donating to later depositors."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-mint-zero-shares-no-revert.yaml"
    WIKI_TITLE = "ERC4626 deposit/mint accepts zero-share outcome without reverting"
    WIKI_DESCRIPTION = "An ERC4626 vault's `deposit(assets, receiver)` (or `mint(shares, receiver)` or the internal `_deposit` helper) computes `shares = previewDeposit(assets)` / `convertToShares(assets)` and, when the integer-rounded result is zero, does not revert. The asset transfer from the caller still executes, but the caller receives no shares. The underlying accrues to `totalAssets()` and is effectively a donati"
    WIKI_EXPLOIT_SCENARIO = "A vault holds 1,000,000 * 1e18 shares backed by 10,000 * 1e6 USDC donated by a first-depositor attacker (standard inflation setup). A user deposits 5 USDC expecting some share of the vault. `shares = 5e6 * 1_000_000e18 / 10_000e6 = 500_000_000_000_000` — but on a differently-tuned vault the rounding threshold lands at zero; `deposit()` does not revert, pulls 5 USDC from the user, and mints 0 share"
    WIKI_RECOMMENDATION = "Add `require(shares > 0, \"ZeroShares\")` (or the custom-error equivalent `if (shares == 0) revert ZeroShares();`) immediately after computing `shares = previewDeposit(assets)` and before the `_deposit` / asset pull. Do the symmetric check in `mint` on the `assets` return of `previewMint` if your va"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['ERC4626', 'IERC4626', 'ERC4626Upgradeable']}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|_deposit|mint|_mint)$'}, {'function.body_contains_regex': 'previewDeposit|convertToShares|_convertToShares|shares\\s*=\\s*'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*shares\\s*>\\s*0|require\\s*\\(.*shares\\s*!=\\s*0|ZeroShares\\s*\\(\\s*\\)|revert\\s+NoShares'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-mint-zero-shares-no-revert: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
