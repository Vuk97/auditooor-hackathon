"""
pause-asymmetric-blocks-only-some-actions — generated from reference/patterns.dsl/pause-asymmetric-blocks-only-some-actions.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pause-asymmetric-blocks-only-some-actions.yaml
Source: codex-plan-a2d11a06-engagement-5-graphtallycollector
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PauseAsymmetricBlocksOnlySomeActions(AbstractDetector):
    ARGUMENT = "pause-asymmetric-blocks-only-some-actions"
    HELP = "Same contract has a pause lever (`pause()` / `whenNotPaused`) gating its value-flow path (transfer/withdraw/deposit/stake) but admin/config writers (setRate, setFee, setCollector) on the same contract bypass the guard. Pausing the system halts user money but lets governance keep mutating critical pa"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pause-asymmetric-blocks-only-some-actions.yaml"
    WIKI_TITLE = "Asymmetric pause: value-flow gated by whenNotPaused but config writers escape the guard"
    WIKI_DESCRIPTION = "A Pausable contract (defines `pause()` and at least one `whenNotPaused`-guarded transfer/deposit/withdraw path) ALSO exposes admin setters (`setRate`, `setFee`, `setConfig`, `addCollector`, `setRecipient`) that DON'T carry `whenNotPaused`. The pause is therefore one-sided: the operator can stop user value flow but a compromised or rushed admin can still rewrite rates/fees/recipients while the syst"
    WIKI_EXPLOIT_SCENARIO = "(1) Operator detects an exploit and calls `pause()`. (2) `transfer()` / `claim()` correctly revert with `Paused`. (3) A compromised signer or governance attacker now calls `setRate(maliciousRate)` or `setRecipient(attackerAddr)` — neither has `whenNotPaused`, so they execute against the paused contract. (4) Operator calls `unpause()`. (5) Next user interaction routes value at the attacker-controll"
    WIKI_RECOMMENDATION = "Decide explicitly per setter whether it should keep working under pause. For most config writers (rates, fees, recipients, collectors, whitelists) the safe default is to add `whenNotPaused` so the freeze covers BOTH user value flow AND the parameters that govern it. For setters that genuinely must r"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'whenNotPaused|function\\s+paused\\s*\\(|Pausable'}, {'contract.has_function_matching': '^(pause|_pause|pauseAll|pauseDeposits|pauseWithdrawals)$'}, {'contract.has_function_body_matching': 'function\\s+(transfer|withdraw|deposit|stake|claim|redeem|swap|borrow|repay|liquidate)[A-Za-z0-9_]*[^{]{0,200}whenNotPaused'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set[A-Z]\\w+|update[A-Z]\\w+|configure[A-Z]\\w+|add[A-Z]\\w+|remove[A-Z]\\w+|register[A-Z]\\w+|deregister[A-Z]\\w+)$'}, {'function.is_mutating': True}, {'function.body_not_contains_regex': 'whenNotPaused|require\\s*\\(\\s*!\\s*paused|_requireNotPaused'}, {'function.body_contains_regex': '\\b(rate|fee|config|param|collector|recipient|treasury|whitelist|allowlist|threshold|limit)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pause-asymmetric-blocks-only-some-actions: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
