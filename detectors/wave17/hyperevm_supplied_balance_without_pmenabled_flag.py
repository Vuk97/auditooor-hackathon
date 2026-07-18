"""
hyperevm-supplied-balance-without-pmenabled-flag — generated from reference/patterns.dsl/hyperevm-supplied-balance-without-pmenabled-flag.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-supplied-balance-without-pmenabled-flag.yaml
Source: monetrix-c4-2026-04-vault
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmSuppliedBalanceWithoutPmenabledFlag(AbstractDetector):
    ARGUMENT = "hyperevm-supplied-balance-without-pmenabled-flag"
    HELP = "HyperCore SUPPLIED_BALANCE precompile (0x811) is meaningful only after Portfolio-Margin activation AND for explicitly-registered token slots. Reading 0x811 without gating on a `pmEnabled` flag or a registered-slots map can read stale / phantom L1 balances and inflate the protocol's backing aggregate"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-supplied-balance-without-pmenabled-flag.yaml"
    WIKI_TITLE = "HyperCore suppliedBalance (0x811) read without pmEnabled / registered-slot guard"
    WIKI_DESCRIPTION = "Hyperliquid's Portfolio-Margin (PM) feature exposes a per-account, per-token 'supplied' balance via precompile 0x811 (SUPPLIED_BALANCE). Two preconditions must hold for the read to be meaningful: (1) PM has been activated for the account at the chain level — protocol must explicitly opt-in with a keeper-driven activation action; (2) the specific `(account, token)` slot has been registered on L1 vi"
    WIKI_EXPLOIT_SCENARIO = "Stablecoin protocol on HyperEVM has a multi-asset hedge model. Backing aggregate iterates whitelisted tokens and sums `suppliedBalance(vault, tokenIdx)` for each. PM activation has NOT yet been requested on the vault — keeper hasn't completed the L1 setup. Implementation reads 0x811 unconditionally for every iteration. Result: precompile returns stale values for token slots that look 'live' to L1 "
    WIKI_RECOMMENDATION = "Two-layer gating: (1) a single `bool public pmEnabled` storage flag, flipped only by the keeper after L1 PM activation is verified (e.g. by reading 0x811 against a known-good test slot and checking the value matches an expected sentinel); (2) an explicit registered-slots list, populated by the same "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'suppliedBalance|PRECOMPILE_SUPPLIED_BALANCE|0x0000000000000000000000000000000000000811|portfolioMargin|pmEnabled|isPmActive|portfolio_margin'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'suppliedBalance\\s*\\(|suppliedUsdcEvm\\s*\\(|suppliedNotionalUsdcFromPerp\\s*\\('}, {'function.body_contains_regex': 'for\\s*\\(\\s*uint|while\\s*\\(|\\+=\\s*[a-zA-Z_].*supplied|\\+=\\s*uint256\\s*\\([^)]*supplied|total\\s*\\+=|backing\\s*\\+=|return\\s+[^;]*\\+\\s*[^;]*supplied'}, {'function.body_not_contains_regex': 'pmEnabled|isPmActive|isPmOn|portfolioMarginEnabled|isPortfolioMargin|pm_active|require\\s*\\(\\s*pm|if\\s*\\(\\s*!?\\s*pm|vaultSupplied\\s*\\[|multisigSupplied\\s*\\[|suppliedRegistry|registeredSupply|_vaultSupplyKnown|_multisigSupplyKnown|isSuppliedRegistered'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hyperevm-supplied-balance-without-pmenabled-flag: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
