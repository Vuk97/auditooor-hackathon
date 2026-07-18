"""
recipient-reassignment-only-in-one-branch — generated from reference/patterns.dsl/recipient-reassignment-only-in-one-branch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py recipient-reassignment-only-in-one-branch.yaml
Source: auditooor-R101-base-azul-FN-1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RecipientReassignmentOnlyInOneBranch(AbstractDetector):
    ARGUMENT = "recipient-reassignment-only-in-one-branch"
    HELP = "A `resolve()` / `settle()` style function writes the winning status in BOTH branches of an if/else, but the bond/payout/winner-recipient reassignment is inside only ONE branch. The other branch leaves the recipient pointer at the construction-time default (typically the original proposer / loser par"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/recipient-reassignment-only-in-one-branch.yaml"
    WIKI_TITLE = "Two-branch resolve writes status in both arms but reassigns bondRecipient in only one"
    WIKI_DESCRIPTION = "Optimistic dispute games and similar two-step resolution contracts often have a `resolve()` that branches on parent-game status: one branch propagates an external invalidation (`if (parentStatus == CHALLENGER_WINS) status = CHALLENGER_WINS;`), the other runs the normal challenge/threshold check (`else { if (counteredBy > 0) { status = CHALLENGER_WINS; bondRecipient = challenger; } else status = DE"
    WIKI_EXPLOIT_SCENARIO = "Honest challenger C submits a ZK proof against fraudulent proposer A's child game G1 (parent of G1 is honest game G0). State: `counteredBy[G1] > 0`, `proofTypeToProver[G1, ZK] = C`. Concurrently G0 is blacklisted (separate governance action). Anyone calls `resolve(G1)`. The outer branch fires (parent-status == CHALLENGER_WINS), sets `status = CHALLENGER_WINS`, but never reassigns `bondRecipient` f"
    WIKI_RECOMMENDATION = "Inside the invalid-parent branch, also reassign the recipient: `if (parentStatus == CHALLENGER_WINS) { status = CHALLENGER_WINS; if (counteredBy > 0) bondRecipient = proofTypeToProver[ZK]; }`. Or factor recipient assignment into a single helper called from both branches, taking the current challenge"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Game|Verifier|DisputeGame|Resolution|Settlement|Auction|Challenge|Bond'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?resolve|_?finalize|_?settle|_?settleGame|_?closeGame|_?conclude|_?claimResult)$'}, {'function.body_contains_regex': '\\bif\\s*\\([^)]*(parentGameStatus|parentStatus|status|winner|outcome)\\s*==\\s*[\\w.]*(CHALLENGER|LOSER|INVALID|FAILED|FRAUD)[^)]*\\)\\s*\\{(?:(?!bondRecipient|payoutRecipient|winner\\s*=|recipient\\s*=|payout\\s*=|prizeRecipient)[^}])*\\bstatus\\s*=\\s*[^;]*?(?:CHALLENGER|LOSER|INVALID|FAILED|FRAUD)[^;]*;(?:(?!bondRecipient|payoutRecipient|winner\\s*=|recipient\\s*=|payout\\s*=|prizeRecipient)[^}])*\\}'}, {'function.body_contains_regex': '\\b(bondRecipient|payoutRecipient|recipient|payout|prizeRecipient)\\s*=\\s*[A-Za-z_]|\\bwinner\\s*=\\s*[A-Za-z_]'}, {'function.body_contains_regex': '\\belse\\s*\\{[^}]*\\bstatus\\s*=\\s*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — recipient-reassignment-only-in-one-branch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
