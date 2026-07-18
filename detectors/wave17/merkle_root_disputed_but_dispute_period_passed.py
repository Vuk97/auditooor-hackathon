"""
merkle-root-disputed-but-dispute-period-passed — generated from reference/patterns.dsl/merkle-root-disputed-but-dispute-period-passed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-root-disputed-but-dispute-period-passed.yaml
Source: solodit/c4/angle-H03-20817
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleRootDisputedButDisputePeriodPassed(AbstractDetector):
    ARGUMENT = "merkle-root-disputed-but-dispute-period-passed"
    HELP = "Canonical-root / canonical-price getter treats `block.timestamp >= endOfDisputePeriod` as sufficient for finality, without checking whether a dispute was actually raised. A dispute filed late (and not yet resolved) still lets the malicious root be claimed against."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-root-disputed-but-dispute-period-passed.yaml"
    WIKI_TITLE = "Optimistic root finality checks only the clock, not the dispute flag"
    WIKI_DESCRIPTION = "Merkle-distributor / oracle / rollup contracts gate their 'canonical commitment' behind a dispute window: a fresh commit is provisional until `endOfDisputePeriod`, after which it becomes authoritative. If a dispute lands close to the deadline and the governor/guardian hasn't yet resolved it, a getter that only checks the clock opens claims against the commitment. Attackers pair (a) publishing a ma"
    WIKI_EXPLOIT_SCENARIO = "Publisher submits a malicious Merkle tree that lets their EOA claim the full DAI balance. A user calls `disputeTree(hash)`, setting `disputer = user`. The governor is on vacation for 24h. `endOfDisputePeriod` arrives. Publisher calls `claim(proof, amount = balance)`. `getMerkleRoot()` checks `block.timestamp >= endOfDisputePeriod` (true), returns the malicious `tree.merkleRoot`. Claim verifies and"
    WIKI_RECOMMENDATION = "Harden the getter: `if (block.timestamp >= endOfDisputePeriod && disputer == address(0)) return tree.merkleRoot; else return lastTree.merkleRoot;`. Treat a pending dispute as strictly blocking, independent of time. Consider additionally extending the dispute period on any new dispute so late-filed d"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(endOfDisputePeriod|disputePeriod|disputer|challenger|challenge)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '^(getMerkleRoot|getRoot|getCanonical|getCanonicalRoot|currentRoot|currentMerkleRoot|activeRoot|activeMerkleRoot|getLatest|getLatestRoot|getLatestMerkleRoot)$'}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': 'block\\.timestamp\\s*>=\\s*endOfDisputePeriod|block\\.timestamp\\s*>=\\s*\\w*[Dd]isputeDeadline|block\\.timestamp\\s*>\\s*\\w*Challenge'}, {'function.body_not_contains_regex': 'disputer\\s*==\\s*address\\s*\\(\\s*0\\s*\\)|!disputed|challenger\\s*==\\s*address\\s*\\(\\s*0\\s*\\)|challenge\\s*==\\s*bytes32\\s*\\(\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — merkle-root-disputed-but-dispute-period-passed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
