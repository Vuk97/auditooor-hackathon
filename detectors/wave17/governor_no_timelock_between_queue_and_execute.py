"""
governor-no-timelock-between-queue-and-execute — generated from reference/patterns.dsl/governor-no-timelock-between-queue-and-execute.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governor-no-timelock-between-queue-and-execute.yaml
Source: beanstalk-2022-exploit-anchor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernorNoTimelockBetweenQueueAndExecute(AbstractDetector):
    ARGUMENT = "governor-no-timelock-between-queue-and-execute"
    HELP = "Governor's queue-and-execute path flips a queued proposal to executed with no timelock delay between the two — flashloan-voting attackers can queue + execute in one transaction, as in the Beanstalk 2022 $182M exploit."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governor-no-timelock-between-queue-and-execute.yaml"
    WIKI_TITLE = "Governor executes queued proposal with no timelock delay between queue and execute (Beanstalk class)"
    WIKI_DESCRIPTION = "A governance contract records a dedicated `queued` / `queuedAt` / `Queued` proposal state but its `execute()` / `executeProposal()` path consumes that state with no `eta`, `TIMELOCK_DELAY`, `GRACE_PERIOD`, or `block.timestamp >= eta` gate. The queued-flag is therefore just a bookkeeping marker, not a delay: any caller who can flip a proposal to Queued can flip it to Executed in the very next call "
    WIKI_EXPLOIT_SCENARIO = "Beanstalk 2022 ($182M): attacker flash-borrowed ~$1B of stables, minted a supermajority of BEAN3CRV and BEANLUSD LP tokens, called emergencyCommit on a pre-seeded proposal whose queued flag flipped to true inside the same tx, then immediately executed the proposal to drain the reserves and repay the flashloan. The queue-step set `_queued[id] = true` but the execute-step never checked any delay bef"
    WIKI_RECOMMENDATION = "Between queue and execute require a minimum delay: set `proposals[id].eta = block.timestamp + TIMELOCK_DELAY` in queue() and require `block.timestamp >= proposals[id].eta` in execute(). Prefer routing execution through OpenZeppelin `TimelockController` (separate proposer/executor roles, `getMinDelay"

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(proposal|proposals|_proposals|governance)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(execute|executeProposal|performProposal|callProposal)$'}, {'function.body_matches_regex': '(proposals\\[|_proposals\\[)'}, {'function.body_matches_regex': '(queuedAt\\s*==|_queued\\[\\w+\\]\\s*==\\s*true|\\.queued\\s*==\\s*true|state\\s*==\\s*(State\\.)?Queued)'}, {'function.body_not_matches_regex': '(timelock|TIMELOCK|delay|DELAY|eta\\s*<=\\s*block\\.timestamp|block\\.timestamp\\s*>=\\s*\\w*(eta|executionTime|readyAt|delayEnd)|GRACE_PERIOD|canExecute)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governor-no-timelock-between-queue-and-execute: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
