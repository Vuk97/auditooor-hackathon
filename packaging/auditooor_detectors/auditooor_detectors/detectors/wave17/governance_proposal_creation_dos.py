"""
governance-proposal-creation-dos — generated from reference/patterns.dsl/governance-proposal-creation-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governance-proposal-creation-dos.yaml
Source: solodit-cluster/C0296
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernanceProposalCreationDos(AbstractDetector):
    ARGUMENT = "governance-proposal-creation-dos"
    HELP = "Governance propose/cancel uses a threshold or id check that can be griefed by an attacker (strict >=, adversary-controllable counter, caller-supplied id with no dedup)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governance-proposal-creation-dos.yaml"
    WIKI_TITLE = "Governance proposal creation DoS / griefing"
    WIKI_DESCRIPTION = "A governance entrypoint (propose, createProposal, cancelProposal) uses an unsafe check against an adversary-controllable quantity. Typical failures: (a) `require(votes >= proposalThreshold)` with strict `>=` lets anyone front-run and cancel a proposal that has exactly `proposalThreshold` votes, (b) caller-supplied `proposalId` / `name` / `ballot` with no dedup or allowlist lets an attacker reserve"
    WIKI_EXPLOIT_SCENARIO = "An attacker watches the mempool for a `propose(...)` tx. They front-run it by submitting a proposal with the same caller-supplied id / ballot name; the real transaction now reverts on the `proposals[id]` collision check, blocking every proposal indefinitely. Alternatively, a proposal sits at exactly the threshold number of votes and the attacker calls `cancelProposal` using the strict-equality can"
    WIKI_RECOMMENDATION = "Use server-assigned, monotonically increasing proposal ids (`proposalId = ++nextId`) rather than caller-supplied values. Add explicit dedup: `require(!proposals[id].exists)` or `EnumerableSet.add` with a bool return check. For threshold checks, use strict `>` instead of `>=` so an exact-equality can"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'proposal|proposalThreshold|quorum|proposals'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'propose|createProposal|submitProposal|cancel|cancelProposal'}, {'function.body_contains_regex': {'regex': 'proposalThreshold|proposals\\[|proposalId|votes\\s*(>=|==)|threshold\\s*(>=|==)'}}, {'function.body_not_contains_regex': 'require\\s*\\(.*(!proposals\\[|!hasProposal|!exists|isAllowed)|EnumerableSet\\.contains'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governance-proposal-creation-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
