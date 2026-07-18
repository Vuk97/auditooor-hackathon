"""
bridge-commitment-transcript-no-domain-separator — generated from reference/patterns.dsl/bridge-commitment-transcript-no-domain-separator.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-commitment-transcript-no-domain-separator.yaml
Source: snowbridge-ba20bc65-audit-issue-7-sibling-batch6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeCommitmentTranscriptNoDomainSeparator(AbstractDetector):
    ARGUMENT = "bridge-commitment-transcript-no-domain-separator"
    HELP = "Bridge/finality commitment transcript uses sha256(bytes.concat(sha256(bytes.concat(commitment, bitfield, root)))) without a domain separator constant. Replay across validator-set contexts."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-commitment-transcript-no-domain-separator.yaml"
    WIKI_TITLE = "Bridge commitment transcript hash omits domain separator"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Sibling of bridge-fiat-shamir-transcript-omits-validator-set-domain. A bridge or finality verifier computes a double-sha256 transcript of commitment, bitfield, and validator-set root bytes without an outer domain separator constant. The transcript can be replayed across different validator sets that share the same root bytes."
    WIKI_EXPLOIT_SCENARIO = "BeefyClient derives a random validator subset from sha256(bytes.concat(sha256(bytes.concat(commitmentHash, bitFieldHash, validatorSetRoot)))). Without a fixed domain constant in the outer layer and without validator-set id/length in the inner layer, two validator sets with identical roots produce identical transcripts and therefore identical sampled subsets."
    WIKI_RECOMMENDATION = "Add a protocol-specific domain separator constant to the outer sha256 preimage: sha256(bytes.concat(PROTOCOL_DOMAIN_ID, sha256(bytes.concat(commitment, bitfield, vset.root, vset.id, vset.length)))). This binds the transcript to the protocol and to the specific validator-set identity."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|beefy|finality|validatorSet|validator|commitment|bitfield|beacon|relay)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.source_matches_regex': '(?i)\\bbytes32\\b.*\\b(commitmentHash|commitment_hash|commitHash|blockHash)\\b'}, {'function.source_matches_regex': '(?i)\\bbytes32\\b.*\\b(bitFieldHash|bitfieldHash|bitfield_hash|messageHash|headerHash)\\b'}, {'function.body_contains_regex': '(?is)sha256\\s*\\(\\s*bytes\\.concat\\s*\\(\\s*sha256\\s*\\(\\s*bytes\\.concat\\s*\\('}, {'function.body_not_contains_regex': '(?is)bytes\\.concat\\s*\\([^;{}]*\\b[A-Z][A-Z0-9_]{4,}\\b[^;{}]*sha256'}, {'function.body_not_contains_regex': '(?i)(vset\\.id|validatorSetId|validatorSetID|validator_set_id|authoritySetId|authoritySetID)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — bridge-commitment-transcript-no-domain-separator: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
