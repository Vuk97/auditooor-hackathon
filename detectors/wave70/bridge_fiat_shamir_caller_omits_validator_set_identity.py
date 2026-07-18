"""
bridge-fiat-shamir-caller-omits-validator-set-identity — generated from reference/patterns.dsl/bridge-fiat-shamir-caller-omits-validator-set-identity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-fiat-shamir-caller-omits-validator-set-identity.yaml
Source: slice43-realworld-recall-snowbridge-ba20bc65
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeFiatShamirCallerOmitsValidatorSetIdentity(AbstractDetector):
    ARGUMENT = "bridge-fiat-shamir-caller-omits-validator-set-identity"
    HELP = "Bridge/finality Fiat-Shamir caller computes the bitfield transcript from commitment, bitfield, and validator-set root while leaving validator-set id/domain outside the challenge."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-fiat-shamir-caller-omits-validator-set-identity.yaml"
    WIKI_TITLE = "Fiat-Shamir caller omits validator-set identity from challenge"
    WIKI_DESCRIPTION = "Bridge finality clients often split Fiat-Shamir transcript construction across a helper and a caller that computes the bitfield and validator-set context. If the caller passes only the validator-set root into the transcript helper, the challenge is not bound to the validator-set id, length, or a protocol domain. A fixed design should pass a full validator-set object or explicit root/id/length/doma"
    WIKI_EXPLOIT_SCENARIO = "Snowbridge pre-fix `BeefyClient.fiatShamirFinalBitfield` computed `bitFieldHash` and called `createFiatShamirHash(commitmentHash, bitFieldHash, vsetRoot)`. The challenge path therefore depended on root but not validator-set id/length/domain. The fixed shape routes those identity fields into the Fiat-Shamir transcript."
    WIKI_RECOMMENDATION = "Make the Fiat-Shamir challenge helper accept a full validator-set identity or explicit domain/root/id/length fields, and assert with a regression test that same-root validator sets with different id or length derive different bitfields."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|beefy|finality|validatorSet|validator set|bitfield|Fiat.?Shamir)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^(fiatShamirFinalBitfield|createFiatShamirFinalBitfield|verifyFiatShamirCommitment|submitFiatShamir)$|.*Fiat.?Shamir.*(?:Bitfield|Commitment|Final).*'}, {'function.body_contains_regex': '(?i)\\b(bitFieldHash|bitfieldHash|bitfield_hash)\\b|keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\(\\s*bitfield\\s*\\)'}, {'function.body_contains_regex': '(?i)\\bcreateFiatShamirHash\\s*\\('}, {'function.body_contains_regex': '(?is)createFiatShamirHash\\s*\\(\\s*(commitmentHash|commitment_hash)\\s*,\\s*(bitFieldHash|bitfieldHash|bitfield_hash)\\s*,\\s*(vsetRoot|validatorSetRoot|validator_set_root|vset\\.root)\\s*\\)'}, {'function.body_contains_regex': '(?i)(vsetLength|validatorSetLength|validatorSetLen|validator_set_len|vset\\.length)'}, {'function.body_not_contains_regex': '(?is)createFiatShamirHash\\s*\\([^;{}]*(FIAT_SHAMIR_DOMAIN_ID|domainSeparator|domainId|domain_id|DST|TRANSCRIPT_DOMAIN|PROTOCOL_DOMAIN|vset\\.id|validatorSetID|validatorSetId|validator_set_id|authoritySetID|authoritySetId|vset\\.length|validatorSetLen|validatorSetLength|validator_set_len|authoritySetLen|authoritySetLength)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — bridge-fiat-shamir-caller-omits-validator-set-identity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
