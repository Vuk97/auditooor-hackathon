"""
timelock-immediate-execute — generated from reference/patterns.dsl/timelock-immediate-execute.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py timelock-immediate-execute.yaml
Source: solodit-timelock-bypass-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TimelockImmediateExecute(AbstractDetector):
    ARGUMENT = "timelock-immediate-execute"
    HELP = "Admin-gated path executes a queued action without honoring the configured timelock delay — the delay is advertised as a governance safeguard but is bypassable by the same role that set it."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/timelock-immediate-execute.yaml"
    WIKI_TITLE = "Timelock bypass: admin-gated executeImmediate / cancelTimelock"
    WIKI_DESCRIPTION = "Timelock contracts exist to give token holders a window to react before a privileged action (upgrade, parameter change, treasury move) takes effect. When the same admin role that configured the `delay` / `minDelay` / `eta` exposes an `executeImmediate`, `bypassTimelock`, `overrideDelay`, `cancelTimelock`, or `emergencyExecute` path, the delay becomes a marketing claim rather than a safeguard: the "
    WIKI_EXPLOIT_SCENARIO = "Protocol advertises a 48-hour timelock on upgrades. A malicious or compromised owner queues an upgrade to a malicious implementation, then calls `executeImmediate(upgradeId)` in the same transaction, skipping the 48h wait. Users who relied on the timelock window to withdraw before the upgrade have no opportunity to react. Alternatively, governance queues a harmful action; the admin calls `cancelTi"
    WIKI_RECOMMENDATION = "Remove admin-bypass paths entirely. A timelock with a privileged override is not a timelock. If break-glass emergency execution is genuinely required, gate it behind multisig + independent guardian + on-chain veto, and emit an immediate event; do not let the same role that sets `delay` also skip it."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(delay|timelock|minDelay|gracePeriod|eta)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(executeImmediate|executeInstant|_executeNow|bypassTimelock|cancelTimelock|overrideDelay|emergencyExecute)'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — timelock-immediate-execute: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
