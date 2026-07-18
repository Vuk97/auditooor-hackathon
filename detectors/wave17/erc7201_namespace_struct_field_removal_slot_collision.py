"""
erc7201-namespace-struct-field-removal-slot-collision — generated from reference/patterns.dsl/erc7201-namespace-struct-field-removal-slot-collision.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc7201-namespace-struct-field-removal-slot-collision.yaml
Source: snowbridge-r109-source-mine-oak-v2-major-finding-2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc7201NamespaceStructFieldRemovalSlotCollision(AbstractDetector):
    ARGUMENT = "erc7201-namespace-struct-field-removal-slot-collision"
    HELP = "ERC-7201 namespaced storage struct had a field removed mid-struct (typically a mapping) and a new field — often a SparseBitmap / BitMap / counter — was placed at the same slot. The new field reads non-zero garbage from leftover keccak-derived entries of the old mapping and treats it as legitimate st"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc7201-namespace-struct-field-removal-slot-collision.yaml"
    WIKI_TITLE = "ERC-7201 namespaced storage struct field removal causes slot collision (mapping tombstone)"
    WIKI_DESCRIPTION = "ERC-7201 (`keccak256('namespace.storage') - 1`) is the modern proxy-storage standard recommended by OpenZeppelin v5 for upgradeable contracts. A single `Layout` struct lives at the namespace base slot; field offsets are determined by struct ordering. Unlike inheritance-based linearization, ERC-7201 has no `__gap`-based mitigation for adding/removing fields between versions. When a maintainer remov"
    WIKI_EXPLOIT_SCENARIO = "Bridge upgrade replaces a `mapping(bytes32 => address) agentAddresses` field in a CoreStorage Layout with a `SparseBitmap inboundNonce`. After the upgrade, the bitmap's underlying word storage contains the lower-160-bits of removed agent addresses. A legitimate inbound-V2 message arrives with nonce N where N maps (via `N >> 8`) to a word that previously held a populated agent slot. `inboundNonce.g"
    WIKI_RECOMMENDATION = "When evolving an ERC-7201 namespaced struct: NEVER remove a field. If a field is logically obsolete, leave it in place and add a new field at the END of the struct. If field removal is unavoidable, replace the field with an equivalently-sized `__gap` placeholder (`uint256 __gap_<old_name>;` for fixe"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'keccak256\\s*\\(\\s*["\'][^"\']*\\.storage\\.[^"\']*["\']\\s*\\)'}, {'contract.source_matches_regex': '(?i)(?://\\s*(?:removed|deprecated|legacy).*(?:mapping|field|slot)|/\\*[\\s\\S]*?(?:removed|deprecated|legacy)[\\s\\S]*?\\*/|mapping\\s*\\([^)]*\\)\\s+\\w+\\s*;[\\s\\S]{0,200}(?:SparseBitmap|BitMap|BitMaps\\.\\w+|mapping\\s*\\([^)]*\\)\\s+\\w+\\s*;))'}, {'contract.source_not_contains_regex': '\\buint(?:8|16|32|64|128|256)\\s*\\[\\s*\\d+\\s*\\]\\s*(?:__gap|_reserved|_storage_gap|_padding)\\b|\\b(?:__gap|_reserved|_storage_gap|_padding)\\s*\\[\\s*\\d+\\s*\\]\\s*;'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'assembly\\s*\\{\\s*\\$\\.slot\\s*:=\\s*'}, {'function.not_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc7201-namespace-struct-field-removal-slot-collision: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
