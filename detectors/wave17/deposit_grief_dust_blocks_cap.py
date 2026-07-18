"""
deposit-grief-dust-blocks-cap — generated from reference/patterns.dsl/deposit-grief-dust-blocks-cap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deposit-grief-dust-blocks-cap.yaml
Source: solodit-cluster-C0214
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DepositGriefDustBlocksCap(AbstractDetector):
    ARGUMENT = "deposit-grief-dust-blocks-cap"
    HELP = "Deposit function enforces a global cap via running-total comparison but has no minimum-deposit floor — attacker fills the cap with 1-wei dust deposits across throwaway addresses, bricking deposits for everyone."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deposit-grief-dust-blocks-cap.yaml"
    WIKI_TITLE = "Deposit griefing: dust deposits exhaust the global cap"
    WIKI_DESCRIPTION = "Vault- and pool-style contracts enforce a maximum total deposit via `require(totalDeposited + amount <= cap)`. When the function accepts arbitrarily small amounts, an attacker can iterate 1-wei deposits across unlimited addresses to saturate the cap. Once saturated, every honest depositor reverts at the cap check and protocol TVL is permanently stuck below the intended ceiling, at a griefing cost "
    WIKI_EXPLOIT_SCENARIO = "A lending market caps total deposits at 100M USDC. Deposit accepts any positive `amount` and increments `totalDeposited`. Attacker scripts 100M sequential deposits of 1 wei each from fresh EOAs (or one CREATE2 factory), consuming ~$10 in L2 gas. The cap is now satisfied by worthless dust. Every legitimate LP reverts at `totalDeposited + amount > cap`, permanently DoS-ing the protocol's deposit rai"
    WIKI_RECOMMENDATION = "Enforce a non-trivial minimum deposit via `require(amount >= MIN_DEPOSIT)` sized so the attack cost (minDeposit * cap / minDeposit = cap) approximates the full cap. Alternatively, impose a per-address deposit limit so one attacker cannot iterate unlimited fresh addresses, or charge a non-refundable "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'cap|maxDeposit|depositCap|maxTvl|totalDeposited'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'deposit|_deposit|provide|supply|joinPool'}, {'function.body_contains_regex': {'regex': 'totalDeposited|totalSupplied|cap|maxTvl', 'negate': False}}, {'function.body_not_contains_regex': 'minDeposit|MIN_DEPOSIT|require\\s*\\(.*amount\\s*>=?\\s*\\d|require\\s*\\(.*amount\\s*>=?\\s*MIN'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deposit-grief-dust-blocks-cap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
