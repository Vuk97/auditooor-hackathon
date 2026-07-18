"""
bridge-fiat-shamir-transcript-omits-validator-set-domain — generated from reference/patterns.dsl/bridge-fiat-shamir-transcript-omits-validator-set-domain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-fiat-shamir-transcript-omits-validator-set-domain.yaml
Source: snowbridge-ba20bc65-audit-issue-7
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeFiatShamirTranscriptOmitsValidatorSetDomain(AbstractDetector):
    ARGUMENT = "bridge-fiat-shamir-transcript-omits-validator-set-domain"
    HELP = "Bridge/finality verifier derives a Fiat-Shamir transcript from commitment, bitfield, and validator-set root but omits a protocol domain separator and validator-set id/length."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-fiat-shamir-transcript-omits-validator-set-domain.yaml"
    WIKI_TITLE = "Fiat-Shamir transcript omits validator-set domain binding"
    WIKI_DESCRIPTION = "Bridge finality clients commonly use a Fiat-Shamir transcript to select a sampled validator subset. The transcript must bind the protocol domain and the validator-set identity, not only the set root. If the challenge hashes only `(commitmentHash, bitFieldHash, validatorSetRoot)`, the same transcript can be replayed across validator-set contexts that share a root or across protocol domains that reu"
    WIKI_EXPLOIT_SCENARIO = "Snowbridge `BeefyClient.createFiatShamirHash` before commit ba20bc65 derived `sha256(sha256(commitmentHash, bitFieldHash, validatorSetRoot))`. Audit Issue 7 changed the transcript to include `FIAT_SHAMIR_DOMAIN_ID`, `vset.root`, `vset.id`, and `vset.length`. Without those fields, the random validator sample is not scoped to the validator-set identity the bridge is validating."
    WIKI_RECOMMENDATION = "Domain-separate the transcript and bind all validator-set identity fields used by the verifier: `sha256(FIAT_SHAMIR_DOMAIN_ID || sha256(commitmentHash || bitFieldHash || vset.root || vset.id || vset.length))`. Add a regression test that two validator sets with the same root but different id/length d"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|beefy|finality|validatorSet|validator set|commitment|bitfield|Fiat.?Shamir)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^(createFiatShamirHash|deriveFiatShamirChallenge|computeFiatShamirHash)$|(?:create|derive|compute).*Fiat.?Shamir.*(?:Hash|Challenge)'}, {'function.source_matches_regex': '(?i)(sha256|keccak256)\\s*\\('}, {'function.source_matches_regex': '(?i)(commitmentHash|commitment_hash)'}, {'function.source_matches_regex': '(?i)(bitFieldHash|bitfieldHash|bitfield_hash)'}, {'function.source_matches_regex': '(?i)(validatorSetRoot|validator_set_root|vset\\.root)'}, {'function.not_source_matches_regex': '(?is)bytes\\.concat\\s*\\([^;{}]*(FIAT_SHAMIR_DOMAIN_ID|domainSeparator|domainId|domain_id|DST|TRANSCRIPT_DOMAIN|PROTOCOL_DOMAIN)'}, {'function.not_source_matches_regex': '(?is)bytes\\.concat\\s*\\([^;{}]*(vset\\.root|validatorSetRoot|validator_set_root)[^;{}]*(vset\\.id|validatorSetID|validatorSetId|validator_set_id|authoritySetID|authoritySetId)[^;{}]*(vset\\.length|validatorSetLength|validatorSetLen|validator_set_len|authoritySetLen|authoritySetLength)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — bridge-fiat-shamir-transcript-omits-validator-set-domain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
