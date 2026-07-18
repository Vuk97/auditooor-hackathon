"""
erc4626-first-depositor-share-price-manip — generated from reference/patterns.dsl/erc4626-first-depositor-share-price-manip.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-first-depositor-share-price-manip.yaml
Source: solodit-cluster/C0261
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626FirstDepositorSharePriceManip(AbstractDetector):
    ARGUMENT = "erc4626-first-depositor-share-price-manip"
    HELP = "ERC4626-style vault deposit / mint / preview function computes shares as assets * totalSupply / totalAssets with no virtual-shares, decimalsOffset, DEAD_SHARES, or seeded-initializer mitigation — first depositor can donate underlying to inflate share price and steal later depositors' stakes."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-first-depositor-share-price-manip.yaml"
    WIKI_TITLE = "ERC4626 first-depositor inflation attack (donation-based share-price manipulation)"
    WIKI_DESCRIPTION = "An ERC4626 vault (canonical or re-implementation) exposes a deposit / mint path that computes shares as `assets * totalSupply / totalAssets` without any first-depositor mitigation. The attacker is the first depositor, mints 1 wei of shares, then transfers underlying directly into the vault (donation) so totalSupply=1 and totalAssets is huge. Subsequent depositors compute `shares = assets * 1 / lar"
    WIKI_EXPLOIT_SCENARIO = "Attacker calls vault.deposit(1 wei) as the first depositor, receives 1 share. Attacker transfers 10,000 DAI directly to the vault contract (bypassing deposit). Alice then calls vault.deposit(5,000 DAI) expecting ~half the vault's shares. The vault computes shares = 5,000e18 * 1 / 10,000e18 = 0 (integer truncation); Alice receives zero shares but the vault's assets ledger grows to 15,000 DAI. Attac"
    WIKI_RECOMMENDATION = "Use the OpenZeppelin v4.9+ ERC4626 base which includes `_decimalsOffset()` virtual-shares protection by default. Alternatively: (1) mint and permanently burn a MINIMUM_SHARES amount to address(0) / DEAD_ADDRESS on the first deposit (ERC20-V2 style); (2) seed the vault in the constructor/initializer "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['ERC4626', 'IERC4626', 'ERC4626Upgradeable', 'ERC4626Fees']}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': 'deposit|mint|_mint|_convertToShares|previewDeposit|previewMint'}, {'function.body_contains_regex': {'regex': '\\*\\s*totalSupply\\s*\\/|\\*\\s*_totalSupply\\s*\\/|\\*\\s*totalShares\\s*\\/|shares\\s*=\\s*[^;]*totalAssets'}}, {'function.body_not_contains_regex': 'virtualShares|virtualAssets|_decimalsOffset|\\boffset\\b|DEAD_SHARES|MINIMUM_SHARES|DEAD_ADDRESS|_initialize\\s*\\(\\s*\\d|initialDeposit|firstDeposit|MINIMUM_LIQUIDITY'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-first-depositor-share-price-manip: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
