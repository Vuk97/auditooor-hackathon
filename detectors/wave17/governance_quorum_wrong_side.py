"""
governance-quorum-wrong-side — generated from reference/patterns.dsl/governance-quorum-wrong-side.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governance-quorum-wrong-side.yaml
Source: code4arena-2025-01-iq-ai-H-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernanceQuorumWrongSide(AbstractDetector):
    ARGUMENT = "governance-quorum-wrong-side"
    HELP = "Governance quorum / succeeded predicate compares the wrong vote tally (uses againstVotes where it should use forVotes, or ignores one side entirely) — proposals can pass with tiny support."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governance-quorum-wrong-side.yaml"
    WIKI_TITLE = "Governance quorum checked on wrong vote-side"
    WIKI_DESCRIPTION = "An OpenZeppelin-style governor (or fork) overrides `_quorumReached` / `_voteSucceeded` / `state` to plug in custom counting but references the wrong per-side tally. Typical failure modes: (1) the quorum predicate reads `againstVotes >= quorum()` instead of `forVotes >= quorum()` so a proposal passes as long as it has enough against-votes, (2) the succeeded predicate checks only that `forVotes >= q"
    WIKI_EXPLOIT_SCENARIO = "Attacker owns 5% of governance token. They propose a malicious change (treasury drain, parameter wipe). The remaining community votes AGAINST it, accumulating `againstVotes` well in excess of `quorum`. The custom `_quorumReached` reads `againstVotes >= quorum()` and returns true. The override of `_voteSucceeded` returns `forVotes > 0`. The proposal becomes `Succeeded` even though it is overwhelmin"
    WIKI_RECOMMENDATION = "The quorum numerator must include all participating votes (`forVotes + abstainVotes`, per OpenZeppelin v4) or at minimum the supporting side (`forVotes`). The succeeded predicate must additionally compare sides: `forVotes > againstVotes`. Never use `againstVotes` as the primary operand of the quorum"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'forVotes|againstVotes|abstainVotes|_quorum|proposal'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?quorumReached|quorum|_voteSucceeded|voteSucceeded|_succeeded|_proposalPassed|_isSuccess|state|_state)$'}, {'function.body_contains_regex': {'regex': '(againstVotes|forVotes|abstainVotes)\\s*(>=|>|==)\\s*(quorum|_quorum|proposalThreshold)|>=\\s*quorum\\s*\\('}}, {'function.body_not_contains_regex': 'forVotes\\s*\\+\\s*againstVotes|forVotes\\s*>\\s*againstVotes|(\\()?\\s*forVotes\\s*-\\s*againstVotes|againstVotes\\s*\\+\\s*forVotes'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governance-quorum-wrong-side: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
