"""
spearbit-eigenlayer-slashing-queue-withdraw-bypass — generated from reference/patterns.dsl/spearbit-eigenlayer-slashing-queue-withdraw-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py spearbit-eigenlayer-slashing-queue-withdraw-bypass.yaml
Source: auditooor-R75-spearbit-eigenlayer-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SpearbitEigenlayerSlashingQueueWithdrawBypass(AbstractDetector):
    ARGUMENT = "spearbit-eigenlayer-slashing-queue-withdraw-bypass"
    HELP = "Slashing decrements live operator/delegator shares but skips queued withdrawals. An operator queues withdrawal right before a slashing event and completes after — extracting the pre-slash value the restaking contract should have haircut."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/spearbit-eigenlayer-slashing-queue-withdraw-bypass.yaml"
    WIKI_TITLE = "Restaking slash does not write down queued withdrawals"
    WIKI_DESCRIPTION = "A restaking protocol holds delegator shares in `operatorShares[operator]`. Withdrawals transition through a queue (`queueWithdrawal` -> wait delay -> `completeQueuedWithdrawal`). When a slashing event fires, the protocol decrements live operatorShares but leaves the queued-withdrawal records untouched. An operator who observes an incoming slashable action (for example a challenge period on an AVS)"
    WIKI_EXPLOIT_SCENARIO = "Operator has 100 shares delegated. A challenge is raised at T=0; slash will land at T=10. At T=1 operator calls queueWithdrawal(100); operatorShares is now 0 but queuedWithdrawal[op] = 100. At T=10 slash fires expecting to cut 50% — sees operatorShares=0, does nothing. At T=20 (after withdrawal delay) operator completes withdrawal, takes 100 shares of pre-slash underlying assets. Honest delegators"
    WIKI_RECOMMENDATION = "Slashing must haircut both live operatorShares AND every queued withdrawal that belongs to the slashed operator/delegator. Walk the `queuedWithdrawals[op]` list (or a Merkle root + incremental commitments) and apply the same haircut factor. Alternatively, freeze queued withdrawals when a challenge i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'queueWithdrawal|completeQueuedWithdrawal|_slash|slashOperator'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(slash|_slash|slashOperator|slashShares)$'}, {'function.body_contains_regex': 'operatorShares\\s*\\[.*\\]\\s*-=|delegatedShares\\s*-='}, {'function.body_not_contains_regex': 'queuedWithdrawal|_queuedWithdrawals|pending\\s*\\[.*\\]|withdrawalRoot'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — spearbit-eigenlayer-slashing-queue-withdraw-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
