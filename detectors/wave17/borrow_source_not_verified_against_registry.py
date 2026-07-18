"""
borrow-source-not-verified-against-registry — generated from reference/patterns.dsl/borrow-source-not-verified-against-registry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py borrow-source-not-verified-against-registry.yaml
Source: defimon-2026-04-20-juicebox-revloans-52k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BorrowSourceNotVerifiedAgainstRegistry(AbstractDetector):
    ARGUMENT = "borrow-source-not-verified-against-registry"
    HELP = "borrowFrom/loanFrom/cashOutFrom path accepts a caller-supplied (terminal, token) source struct and dereferences `.terminal` for routing without verifying the terminal is registered for the position's project/revnet via the directory registry. Attacker swaps in their own IJBTerminal-shaped contract."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/borrow-source-not-verified-against-registry.yaml"
    WIKI_TITLE = "borrow/loan/cashOut accepts caller-supplied terminal/token source without registry check"
    WIKI_DESCRIPTION = "Multi-terminal lending stacks (Juicebox revnets, similar router-of-routers designs) let projects register multiple terminals where users can pay/redeem. A `borrowFrom(...)` entrypoint takes a `LoanSource(terminal, token)` argument so the caller can specify which terminal to borrow against. The bug: the contract trusts that struct as authoritative and routes the token transfer through `source.termi"
    WIKI_EXPLOIT_SCENARIO = "Juicebox.money REVLoans (Apr 20 2026, ~$51.9K drained, frontrun tx 0xc46cb7af8830b7ff4c2373cce26a7b99cf60c1ad21f348a2358a50ae24dead1f). The exploiter spotted a public mempool `borrowFrom(REVLoanSource(terminal=fakeTerm, token=ETH), ...)` from a legitimate user, frontran with their own `borrowFrom` against the same revnet but supplied an attacker-deployed terminal whose `cashOut` returned the reque"
    WIKI_RECOMMENDATION = "Insert a registry check at the top of every borrow/loan/cashOut/redeem path that takes a caller-supplied terminal: `require(directory.isTerminalOf(revnetId, source.terminal), 'bad terminal');`. Equivalently, look up the terminal from the registry instead of accepting one from the caller — `IJBTermin"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(directory|terminalsOf|primaryTerminal|terminalOf|isTerminal|registeredTerminal|controllerOf|isController|allowedTerminal)'}, {'contract.source_matches_regex': '(?i)struct\\s+\\w*(Source|LoanSource|RouteSource|FundingSource)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(borrow|borrowFrom|loan|loanFrom|cashOut|cashOutFrom|redeem|redeemFrom|drawDebt|takeOut|reborrow)([A-Z_].*)?$'}, {'function.has_param_struct_named': 'Source'}, {'function.body_contains_regex': '(?i)\\.terminal\\b|source\\.terminal'}, {'function.body_not_contains_regex': '(?i)(directory|DIRECTORY|registry|REGISTRY)\\s*\\.\\s*(isTerminalOf|terminalsOf|primaryTerminalOf|controllerOf|isController|hasTerminal)\\s*\\(|require\\s*\\([^)]*\\.terminal\\s*==|require\\s*\\([^)]*isTerminal|require\\s*\\([^)]*terminalsOf|require\\s*\\([^)]*primaryTerminalOf'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — borrow-source-not-verified-against-registry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
