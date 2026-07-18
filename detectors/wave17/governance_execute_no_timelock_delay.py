"""
governance-execute-no-timelock-delay — generated from reference/patterns.dsl/governance-execute-no-timelock-delay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governance-execute-no-timelock-delay.yaml
Source: solodit-governance-timelock-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernanceExecuteNoTimelockDelay(AbstractDetector):
    ARGUMENT = "governance-execute-no-timelock-delay"
    HELP = "Governance execute() runs a successful proposal immediately after voting ends — no timelock delay, so dissenting holders have no window to exit before a hostile majority's payload lands."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governance-execute-no-timelock-delay.yaml"
    WIKI_TITLE = "Governance execute with no timelock delay: immediate post-vote settlement"
    WIKI_DESCRIPTION = "A governance contract exposes an `execute(proposalId)` path that transitions a succeeded proposal to executed state in the same block voting ends, without consulting a timelock delay, `eta`, or external `TimelockController`. This is the canonical asset-grab vector against token governance: a voter bloc accumulates just enough tokens to pass a treasury-drain or upgrade proposal, then lands executio"
    WIKI_EXPLOIT_SCENARIO = "A protocol's governance has 100M voting tokens outstanding. An attacker (or colluding whale group) acquires 51M tokens and submits a proposal to transfer the treasury to their address. Voting ends; `execute(proposalId)` can be called in the next block and requires only that the proposal reached Succeeded state. Honest holders see the vote result but have no opportunity to sell or unstake before th"
    WIKI_RECOMMENDATION = "Route every successful proposal through a timelock delay. Either (a) integrate OpenZeppelin `TimelockController` as the executor role and have `execute()` call `timelock.schedule()` rather than executing inline, or (b) add an `eta = block.timestamp + minDelay` on proposal success and gate `execute()"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(proposal|proposals|voting|governance)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(execute|executeProposal|_execute|_executeProposal)$'}, {'function.body_contains_regex': '(proposal|state\\s*==\\s*(Succeeded|Passed|Approved)|executedAt)'}, {'function.body_not_contains_regex': '(timelock|delay|\\s+eta\\s+|require\\s*\\(\\s*block\\.timestamp\\s*>=?\\s*\\w*(eta|executionTime|delayEnd)|canExecute)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governance-execute-no-timelock-delay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
