"""
op-fault-game-status-not-checked — generated from reference/patterns.dsl/op-fault-game-status-not-checked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py op-fault-game-status-not-checked.yaml
Source: code4arena/slice_ab-Unruggable-M02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OpFaultGameStatusNotChecked(AbstractDetector):
    ARGUMENT = "op-fault-game-status-not-checked"
    HELP = "OP-Stack fault-proof verifier reads dispute-game root without checking the game's status. In-progress or challenger-won games commit incorrect roots."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/op-fault-game-status-not-checked.yaml"
    WIKI_TITLE = "OP fault verifier ingests root from unresolved / challenger-won dispute game"
    WIKI_DESCRIPTION = "Dispute games on OP Stack bridges and CCIP-Read verifiers expose `rootClaim()` that returns the committed root, but are only trustworthy after `gameStatus() == DEFENDER_WINS` AND the finalization window has elapsed. A verifier that reads `rootClaim()` unconditionally will accept stale roots, half-resolved fraud proofs, or challenger-wins games (which indicate the claim was successfully disputed)."
    WIKI_EXPLOIT_SCENARIO = "CCIP-Read verifier calls `dispute.rootClaim()` to bridge a message. Because it does not check status, it ingests a root from an in-progress game. Before the challenge window expires, the proposer is successfully disputed, but the bridge has already forwarded a message authorized by the bad root."
    WIKI_RECOMMENDATION = "Before reading `rootClaim()`, `require(game.status() == GameStatus.DEFENDER_WINS && block.timestamp >= game.resolvedAt() + AIRGAP_SECONDS)`. Reject proxy or Respected-Game-Type games whose status is CHALLENGER_WINS or IN_PROGRESS."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(FaultDisputeGame|OPFault|DisputeGame|rootClaim)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'rootClaim\\s*\\(\\s*\\)|disputeGame\\.rootClaim|\\.root\\s*\\(\\s*\\)'}, {'function.body_not_contains_regex': '(gameStatus|status|GameStatus)\\s*\\(\\s*\\)\\s*==\\s*(GameStatus\\.|DEFENDER_WINS)|resolvedAt|block\\.timestamp\\s*-\\s*resolvedAt|isFinalized'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — op-fault-game-status-not-checked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
