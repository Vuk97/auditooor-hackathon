"""
bridge-versioned-digest-tag-not-bound-to-version-flag — generated from reference/patterns.dsl/bridge-versioned-digest-tag-not-bound-to-version-flag.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-versioned-digest-tag-not-bound-to-version-flag.yaml
Source: snowbridge-r109-source-mine-oak-v2-major-finding-1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeVersionedDigestTagNotBoundToVersionFlag(AbstractDetector):
    ARGUMENT = "bridge-versioned-digest-tag-not-bound-to-version-flag"
    HELP = "A verifier accepts a protocol-version flag and a versioned tag inside the data, but the predicate checks the tag against a CONSTANT rather than against the version-flag-derived constant. A digest signed for version A can pass version-B verification."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-versioned-digest-tag-not-bound-to-version-flag.yaml"
    WIKI_TITLE = "Versioned digest/tag verifier does not bind the inner tag to the protocol-version flag"
    WIKI_DESCRIPTION = "Cross-chain verifiers, EIP-712 signed-message decoders, and tagged-union codecs frequently support multiple protocol versions in parallel. A typical pattern: caller passes `bool isV2` (or an enum / uint8 protocol version), the verifier picks the version-specific constant, and the predicate then checks the data tag. The bug appears when the predicate forgets the second half: it compares the data ta"
    WIKI_EXPLOIT_SCENARIO = "Snowbridge `Verification.isCommitmentInHeaderDigest` (pre-fix): `if (digestItems[i].kind == DIGEST_ITEM_OTHER && digestItems[i].data.length == 33 && digestItems[i].data[0] == DIGEST_ITEM_OTHER_SNOWBRIDGE && commitment == bytes32(digestItems[i].data[1:])) return true;`. The `isV2` flag was checked separately and only when the V1 constant DIDN'T match. An attacker observes a finalized V1 parachain h"
    WIKI_RECOMMENDATION = "Compute the version-specific expected constant ONCE at the top of the verifier (`bytes1 expectedTag = isV2 ? V2_TAG : V1_TAG;`) and use that variable in the predicate. Add a unit test that (a) builds a V1 digest and asserts `verifyV2(...)` returns false, (b) builds a V2 digest and asserts `verifyV1("

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(digest|isV1|isV2|protocolVersion|version[A-Z]|tag|kind)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.source_matches_regex': '\\b(?:bool|uint8|enum)\\s+(?:isV[12]|version|protocolVersion|protocolMode|protocolV\\w*)\\b'}, {'function.body_contains_regex': '\\.(?:kind|tag|version|discriminator)\\s*==\\s*[A-Z_][A-Z0-9_]*'}, {'function.body_contains_regex': '\\.data\\s*\\[\\s*0\\s*\\]\\s*==\\s*[A-Z_][A-Z0-9_]*'}, {'function.body_not_contains_regex': '(?:isV[12]|version|protocolVersion)\\s*\\?\\s*\\w+(?:_V\\d|V\\d)\\s*:'}, {'function.not_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-versioned-digest-tag-not-bound-to-version-flag: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
