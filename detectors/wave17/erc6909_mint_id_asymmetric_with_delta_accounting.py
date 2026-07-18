"""
erc6909-mint-id-asymmetric-with-delta-accounting — generated from reference/patterns.dsl/erc6909-mint-id-asymmetric-with-delta-accounting.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc6909-mint-id-asymmetric-with-delta-accounting.yaml
Source: auditooor-R71-fixdiff-mined-uniswap-v4-d8f7a4d8
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc6909MintIdAsymmetricWithDeltaAccounting(AbstractDetector):
    ARGUMENT = "erc6909-mint-id-asymmetric-with-delta-accounting"
    HELP = "mint/burn uses CurrencyLibrary.fromId(id) (truncates to uint160) for delta accounting but passes raw uint256 `id` into _mint/_burn. Attacker can mint claims at a phantom id whose debit hits a different currency."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc6909-mint-id-asymmetric-with-delta-accounting.yaml"
    WIKI_TITLE = "ERC-6909 claim id truncation mismatch — mint debit and credit keyed to different ids"
    WIKI_DESCRIPTION = "Pool managers that expose mint(to, id, amount) for ERC-6909 claims must use the same id on both sides of the accounting. A common bug is to normalize the id to a 160-bit currency address for the delta ledger (`_accountDelta(CurrencyLibrary.fromId(id), ...)`) while forwarding the raw uint256 id into `_mint(to, id, amount)`. Because `fromId` discards the upper 96 bits, an attacker can craft `id = X "
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 OZ-L03 / Certora-I02 (2024): mint(to, id, amount) computed delta as `CurrencyLibrary.fromId(id)` but stored ERC-6909 balance at `id`. A caller with id = 0x1...0000_<USDC_address> paid USDC but received an un-burnable claim (or could later burn and be credited a different currency)."
    WIKI_RECOMMENDATION = "Compute normalized currency once: `Currency currency = CurrencyLibrary.fromId(id); uint256 normalizedId = currency.toId();` then use `normalizedId` for both `_accountDelta(currency, ...)` and `_mint(to, normalizedId, amount)`. Reject ids whose upper 96 bits are non-zero with explicit `InvalidId` rev"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(mint|burn|mintClaim|burnClaim)$'}, {'function.has_param_name_matching': '^(id|tokenId|currencyId)$'}, {'function.body_contains_regex': 'CurrencyLibrary\\.fromId|Currency\\.wrap\\s*\\(\\s*address\\s*\\(\\s*uint160'}, {'function.body_contains_regex': '_mint\\s*\\([^)]*id|_burn\\s*\\([^)]*id|_burnFrom\\s*\\([^)]*id'}, {'function.body_not_contains_regex': '\\.toId\\s*\\(\\s*\\)|normalizedId|uint160\\(id\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc6909-mint-id-asymmetric-with-delta-accounting: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
