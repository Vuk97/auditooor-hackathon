"""
snapshot-vs-live-withdrawable-drift — generated from reference/patterns.dsl/snapshot-vs-live-withdrawable-drift.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py snapshot-vs-live-withdrawable-drift.yaml
Source: auditooor-PR121-A7-codex-plan-a2d11a06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SnapshotVsLiveWithdrawableDrift(AbstractDetector):
    ARGUMENT = "snapshot-vs-live-withdrawable-drift"
    HELP = "A request/create/delegate flow snapshots a balance into storage that a later accept/execute consumes, but a sibling withdraw/undelegate path can reduce the live backing first — the snapshot drifts above the actual withdrawable amount."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/snapshot-vs-live-withdrawable-drift.yaml"
    WIKI_TITLE = "Snapshot vs live withdrawable drift: request stores balance, sibling withdraw reduces backing before fulfilment"
    WIKI_DESCRIPTION = "A two-step settlement (request -> later accept/execute) snapshots a balance, share, or delegation amount into the request struct at request time. The accept/execute leg trusts that snapshot when paying out / minting / settling. However, between request and accept the user can call a sibling path (withdraw, undelegate, unstake, cancel) that reduces the LIVE underlying balance without writing back t"
    WIKI_EXPLOIT_SCENARIO = "(1) User holds 100 shares delegated to indexer X. (2) User calls `requestUndelegation(X, 100)`; contract writes `request.shares = 100` to storage and emits `UndelegationRequested`. (3) Same block, user calls `undelegate(X, 100)` (the legacy sibling path). The legacy path decrements `delegation.shares = 0` and pays out the user's 100 shares immediately. (4) The cooldown elapses; user calls `fulfilU"
    WIKI_RECOMMENDATION = "On the request leg, atomically lock the live backing equal to the snapshot: either (a) burn / debit the user's principal balance immediately and stash it in an escrow struct that the accept leg releases, (b) flip a per-user `locked` flag that the sibling withdraw/undelegate paths must check and reve"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)(request|create|propose|stake|delegate)[A-Za-z0-9_]*'}, {'contract.has_function_matching': '(?i)(accept|execute|finalize|claim|resolve|fulfil)[A-Za-z0-9_]*'}, {'contract.has_function_matching': '(?i)(withdraw|undelegate|unstake|cancel|redeem)[A-Za-z0-9_]*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(request|create|propose|stake|delegate)[A-Za-z0-9_]*$'}, {'function.body_contains_regex': '(?i)\\.(snapshot|amount|balance|shares|stake|deposit|delegated|principal|backing)\\s*=\\s*[A-Za-z0-9_\\.\\[\\]]*(balanceOf|shares|delegated|principal|amount|backing)'}, {'function.body_not_contains_regex': '(?i)(locked|escrow|reserved|frozen)\\s*\\+?=|safeTransferFrom\\s*\\(\\s*msg\\.sender\\s*,\\s*address\\s*\\(\\s*this\\s*\\)|_burn\\s*\\(\\s*msg\\.sender|delegated\\s*\\[[^\\]]+\\]\\s*-=|shares\\s*\\[[^\\]]+\\]\\s*-='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — snapshot-vs-live-withdrawable-drift: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
