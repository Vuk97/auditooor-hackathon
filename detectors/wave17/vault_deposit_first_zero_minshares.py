"""
vault-deposit-first-zero-minshares — generated from reference/patterns.dsl/vault-deposit-first-zero-minshares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-deposit-first-zero-minshares.yaml
Source: solodit-cluster/C0317
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultDepositFirstZeroMinshares(AbstractDetector):
    ARGUMENT = "vault-deposit-first-zero-minshares"
    HELP = "Vault deposit / mint entrypoint accepts a `minShares` / `minSharesOut` / `minOut` slippage parameter and guards with `require(shares >= minShares)` but never enforces `minShares > 0`. Caller can pass zero to disable the slippage gate, re-enabling first-depositor inflation / sandwich share-price mani"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-deposit-first-zero-minshares.yaml"
    WIKI_TITLE = "Vault deposit minShares slippage gate bypassable with zero"
    WIKI_DESCRIPTION = "A vault deposit / mint / depositForReceiver function exposes a user-supplied slippage parameter (minShares / minSharesOut / minOut) and guards state changes with `require(shares >= minShares)`. The function never enforces `minShares > 0`, so a caller can pass zero and the guard becomes `shares >= 0` — always true. The first-depositor inflation attack (or a sandwich-style share-price manipulation o"
    WIKI_EXPLOIT_SCENARIO = "A vault exposes `deposit(uint256 assets, uint256 minShares)` and enforces `require(shares >= minShares, \"slippage\")`. A MEV bot observes Alice's pending deposit, front-runs it by donating underlying directly to the vault (inflating share price so `assets * totalSupply / totalAssets` rounds to zero for Alice's deposit), and Alice's transaction is not reverted by the slippage guard because her wal"
    WIKI_RECOMMENDATION = "Require `minShares > 0` (or `minSharesOut != 0`) at the top of every vault deposit / mint entrypoint that accepts a slippage parameter. Alternatively: reject the deposit when the user-supplied min is below a protocol-enforced floor (e.g. `minShares >= MIN_SHARES_FLOOR`). Combine with the canonical f"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'totalShares|totalAssets'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': 'deposit|mint|depositForReceiver'}, {'function.has_param_of_type': 'uint256'}, {'function.body_contains_regex': {'regex': 'require\\s*\\(.*shares\\s*>=?\\s*minShares|require\\s*\\(.*received\\s*>=?\\s*minOut'}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*minShares\\s*>\\s*0|require\\s*\\(.*minShares\\s*!=\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-deposit-first-zero-minshares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
