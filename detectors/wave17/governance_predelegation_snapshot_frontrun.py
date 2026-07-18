"""
governance-predelegation-snapshot-frontrun — generated from reference/patterns.dsl/governance-predelegation-snapshot-frontrun.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governance-predelegation-snapshot-frontrun.yaml
Source: auditooor-R75-trailofbits-governance-token-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernancePredelegationSnapshotFrontrun(AbstractDetector):
    ARGUMENT = "governance-predelegation-snapshot-frontrun"
    HELP = "Proposal snapshot block is set to block.number (current block) instead of block.number - 1, so a voter can pre-delegate a flash-loaned balance in the same block as the propose call and have it counted in the snapshot."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governance-predelegation-snapshot-frontrun.yaml"
    WIKI_TITLE = "Pre-delegation snapshot frontrun: proposal snapshot includes same-block delegations"
    WIKI_DESCRIPTION = "OZ Governor / Compound-Bravo derivatives record a proposal's snapshot block on creation. The voting-power lookup later reads `token.getPastVotes(voter, snapshotBlock)` — a read that resolves to the checkpoint that was active AT THE END of `snapshotBlock`. If the implementation sets `snapshotBlock = block.number` (the propose block), any delegate-write that lands IN THE SAME BLOCK as the propose ca"
    WIKI_EXPLOIT_SCENARIO = "Attacker observes that a DAO's quorum is 4M GOV. They flash-borrow 5M GOV into a freshly-deployed wallet W, call `token.delegate(W)` so the W→W checkpoint is written at block N, then in the same block call `governor.propose([malicious action], ...)` which sets `proposalSnapshot = block.number = N`. The flash loan is repaid in the next step of the same tx bundle. Later, at the vote phase, anyone vo"
    WIKI_RECOMMENDATION = "Set the proposal snapshot to `block.number - 1` (or the previous epoch for time-weighted systems). This ensures the snapshot only reads delegate checkpoints that were finalized strictly BEFORE the propose transaction's block, defeating single-block flash-loan-and-delegate attacks. Additionally, if t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)proposal|snapshot|delegatee|checkpoint'}, {'contract.has_function_matching': '(?i)propose|createProposal|submitProposal'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(propose|createProposal|submitProposal|_propose)$'}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.reads_block_number': True}, {'function.body_contains_regex': '(?i)(snapshotBlock|startBlock|proposalSnapshot)\\s*=\\s*block\\.number|snapshot\\s*=\\s*block\\.number'}, {'function.body_not_contains_regex': '(?i)(snapshotBlock|startBlock|proposalSnapshot)\\s*=\\s*block\\.number\\s*-\\s*1|\\bblock\\.number\\s*-\\s*1\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governance-predelegation-snapshot-frontrun: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
