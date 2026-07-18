"""
bridge-version-flag-tag-unchecked — generated from reference/patterns.dsl/bridge-version-flag-tag-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-version-flag-tag-unchecked.yaml
Source: snowbridge-r109-source-mine-oak-v2-major-finding-1-sibling-batch6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeVersionFlagTagUnchecked(AbstractDetector):
    ARGUMENT = "bridge-version-flag-tag-unchecked"
    HELP = "Bridge verifier accepts a protocol-version flag parameter but checks the data[0] tag against an unconditional ALL_CAPS constant instead of a version-selected constant. Version-A digests pass version-B verification."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-version-flag-tag-unchecked.yaml"
    WIKI_TITLE = "Bridge digest verifier ignores version flag in tag comparison"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Sibling of bridge-versioned-digest-tag-not-bound-to-version-flag. A verifier accepts a version flag (isV2, protocolVersion) but compares the data discriminator byte against an unconditional constant. The version flag is present in the function signature but unused in the critical predicate, so both version-A and version-B digests satisfy the"
    WIKI_EXPLOIT_SCENARIO = "isCommitmentInHeaderDigest(commitment, header, isV2) checks data[0] == DIGEST_ITEM_OTHER_SNOWBRIDGE (V1 constant) regardless of isV2. An attacker with a V1-signed header can call the V2 path and pass validation because the predicate ignores the version flag and always checks against the V1 tag."
    WIKI_RECOMMENDATION = "Compute the version-specific tag before the comparison: bytes1 expectedTag = isV2 ? DIGEST_TAG_V2 : DIGEST_TAG_V1; then check data[0] == expectedTag. Add tests proving V1 digests fail V2 checks and vice versa."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(digest|header|commitment|parachain|bridge|beefy|relay)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.source_matches_regex': '\\b(bool|uint8|enum)\\s+\\b(isV[12]|isV2\\w*|protocolVersion|version|protocolMode|versionFlag|schemaVersion)\\b'}, {'function.body_contains_regex': '\\.data\\s*\\[\\s*0\\s*\\]\\s*==\\s*[A-Z_][A-Z0-9_]+'}, {'function.body_contains_regex': '\\.(kind|tag|discriminator|itemType)\\s*==\\s*[A-Z_][A-Z0-9_]+'}, {'function.body_not_contains_regex': '(?:isV[12]|protocolVersion|version|versionFlag|schemaVersion)\\s*\\?\\s*\\w+(?:_V\\d|_v\\d|V\\d)\\s*:'}, {'function.body_not_contains_regex': '(?:if|require|assert)\\s*\\([^;{}]*(?:isV[12]|protocolVersion|version|versionFlag|schemaVersion)[^;{}]*\\)[^;{}]*\\.[^;{}]*\\.data\\s*\\[\\s*0\\s*\\]'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — bridge-version-flag-tag-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
