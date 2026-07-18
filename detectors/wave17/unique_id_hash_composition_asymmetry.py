"""
unique-id-hash-composition-asymmetry — generated from reference/patterns.dsl/unique-id-hash-composition-asymmetry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unique-id-hash-composition-asymmetry.yaml
Source: oz-2025-graph-disputemanager-l-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniqueIdHashCompositionAsymmetry(AbstractDetector):
    ARGUMENT = "unique-id-hash-composition-asymmetry"
    HELP = "Two paired create-style entry points (createIndexingDispute / createQueryDispute style) in the same contract derive a unique-id by hashing user inputs with different field sets. One path omits msg.sender (or another domain-separating field) from the keccak256 pre-image, so distinct callers can colli"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unique-id-hash-composition-asymmetry.yaml"
    WIKI_TITLE = "Unique-id hash composition asymmetry across paired create entry points"
    WIKI_DESCRIPTION = "A contract exposes two related entry points (createIndexingDispute vs createQueryDispute, openOrderA vs openOrderB, submitClaimX vs submitClaimY, ...) that each derive a unique storage-key id by hashing a user-controllable tuple. The two pre-image tuples are NOT symmetric: one path mixes in msg.sender (or another domain-separating field like block.chainid or a typehash) and the sibling path does n"
    WIKI_EXPLOIT_SCENARIO = "Fisherman Alice scans the indexer set, picks AllocationId = 0xDEAD, posts an indexing dispute with bond. Bob, watching the mempool, submits the same `createIndexingDispute(0xDEAD, ...)` with a higher gas tip and front-runs Alice. The disputeId is `keccak256(abi.encode(allocationId))` = `keccak256(0xDEAD)`, identical for both fishermen because msg.sender was not in the pre-image. Bob's dispute land"
    WIKI_RECOMMENDATION = "Always include a caller-domain field in the keccak256 pre-image of any unique-id derivation: `id = keccak256(abi.encode(allocationId, msg.sender))` for fisherman/dispute paths, `id = keccak256(abi.encode(orderFields, msg.sender))` for orderbook paths. Better: route both paired entry points through a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\bkeccak256\\s*\\('}, {'contract.has_function_matching': '^(create|open|submit|register|propose|new|start|launch)[A-Z][A-Za-z0-9]*$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(create|open|submit|register|propose|new|start|launch)[A-Z][A-Za-z0-9]*$'}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode'}, {'function.body_not_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode[^)]*msg\\.sender|_id\\s*\\(|_buildId\\s*\\(|_computeId\\s*\\(|_hashId\\s*\\(|_makeId\\s*\\(|_deriveId\\s*\\(|_uniqueId\\s*\\('}, {'function.body_contains_regex': '(disputes?|orders?|claims?|requests?|positions?|tickets?|jobs?|tasks?|proposals?|loans?|accounts?|sessions?)\\s*\\[\\s*\\w+\\s*\\]\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unique-id-hash-composition-asymmetry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
