"""
multi-signer-consensus-mutation-of-observed-state-breaks-digest — generated from reference/patterns.dsl/multi-signer-consensus-mutation-of-observed-state-breaks-digest.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py multi-signer-consensus-mutation-of-observed-state-breaks-digest.yaml
Source: auditooor-R73-fixdiff-mined-wormhole-f75c7f8884
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MultiSignerConsensusMutationOfObservedStateBreaksDigest(AbstractDetector):
    ARGUMENT = "multi-signer-consensus-mutation-of-observed-state-breaks-digest"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: in multi-signer bridge designs the per-message digest must stay a pure function of observed event data. This row flags mutation of a digested ConsistencyLevel field from a state/RPC-like lookup instead of storing the lookup result in signer-loc"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/multi-signer-consensus-mutation-of-observed-state-breaks-digest.yaml"
    WIKI_TITLE = "Per-signer mutation of ConsistencyLevel leaks into VAA digest, fractures guardian quorum"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Wormhole's Custom Consistency Level (CCL) issue is the motivating shape: signer-local contract/RPC reads decided how long a guardian should wait, but the implementation overwrote `pe.message.ConsistencyLevel`, a field included in the VAA hash. If different signers observe different lookup results, errors, or fork state, the same event can be"
    WIKI_EXPLOIT_SCENARIO = "Emitter publishes a message with ConsistencyLevel=Custom. One signer reads a CCL config and mutates `message.ConsistencyLevel` to Finalized before hashing; another signer reads a different effective value and mutates the same observed message field to Safe. Both saw the same emitted event, but their VAA digests differ because the mutable field is part of the digest, so quorum can fracture on the m"
    WIKI_RECOMMENDATION = "Separate \"what goes into the digest\" from \"what drives local wait/state-machine logic\". In Wormhole, keep message.ConsistencyLevel == Custom (the emitter's own value), and store the contract-derived value as pe.effectiveCL used only for the wait gate. In any multi-signer aggregator, audit every "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ConsistencyLevel|pendingMessage|MessagePublication|VAA|digest'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'cclHandleMessage|handleMessage|normalizeMessage|setConsistency'}, {'function.body_contains_regex': '(pe|pending|msg)\\.(message\\.)?ConsistencyLevel\\s*='}, {'function.body_contains_regex': '(readContract|readConfig|lookUp|lookup|fetchConfig)'}, {'function.body_not_contains_regex': 'effectiveCL|effective_cl|effectiveConsistency|localCL'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — multi-signer-consensus-mutation-of-observed-state-breaks-digest: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
