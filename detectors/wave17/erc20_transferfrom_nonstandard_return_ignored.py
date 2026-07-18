"""
erc20-transferfrom-nonstandard-return-ignored — generated from reference/patterns.dsl/erc20-transferfrom-nonstandard-return-ignored.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc20-transferfrom-nonstandard-return-ignored.yaml
Source: solodit/erc20-return-not-checked
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc20TransferfromNonstandardReturnIgnored(AbstractDetector):
    ARGUMENT = "erc20-transferfrom-nonstandard-return-ignored"
    HELP = "Function calls `token.transferFrom(...)` on a user-supplied ERC-20 without checking the return value and without routing through `SafeERC20`. Tokens that return `false` on failure (rather than revert, e.g. legacy USDT-pattern but with bool) silently skip the pull — the protocol credits the user with"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc20-transferfrom-nonstandard-return-ignored.yaml"
    WIKI_TITLE = "`transferFrom` return value ignored: non-reverting tokens silently skip pulls"
    WIKI_DESCRIPTION = "Solidity ERC-20 integrations must either (a) use OpenZeppelin's `SafeERC20.safeTransferFrom`, which reverts on `false` or missing return data, or (b) explicitly `require(token.transferFrom(...))`. A bare `token.transferFrom(...);` call assumes the token always reverts on failure. Many mainstream tokens — and almost all forked variants — return `false` on `transferFrom` failure without reverting. I"
    WIKI_EXPLOIT_SCENARIO = "Vault `deposit(uint256 amount)` calls `token.transferFrom(msg.sender, address(this), amount); _mint(msg.sender, amount);`. Attacker approves zero allowance (or maxes it out on a blacklisting token and then gets blacklisted). `transferFrom` returns `false` — no revert — and the next line mints the attacker `amount` shares. The vault is now under-collateralised by exactly `amount` of the pulled toke"
    WIKI_RECOMMENDATION = "Switch to `SafeERC20.safeTransferFrom` everywhere. If you cannot take the import, at minimum write `require(token.transferFrom(from, to, amount), \"transferFrom failed\")`. For tokens that return no data (legacy USDT), either whitelist them explicitly with per-token adapters or reject them at listin"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC20|transferFrom|safeTransferFrom'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(deposit|depositFor|depositTo|pull|pullTokens|swap|swapExactIn|buy|buyFor|sell|sellFor|mint|mintFor|mintTo|stake|stakeFor|supply|supplyTo|collect|collectFees|_deposit|_pull|_mint|_stake)$'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.body_contains_regex': '\\.transferFrom\\s*\\('}, {'function.body_not_contains_regex': 'safeTransferFrom|SafeERC20\\.transferFrom|require\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\.transferFrom|require\\s*\\(\\s*success|ok\\s*=\\s*.*transferFrom|bool\\s+\\w+\\s*=\\s*.*transferFrom'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc20-transferfrom-nonstandard-return-ignored: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
