"""
imm-wormhole-uninit-impl-upgrade-selfdestruct — generated from reference/patterns.dsl/imm-wormhole-uninit-impl-upgrade-selfdestruct.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-wormhole-uninit-impl-upgrade-selfdestruct.yaml
Source: immunefi/wormhole-uninitialized-proxy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmWormholeUninitImplUpgradeSelfdestruct(AbstractDetector):
    ARGUMENT = "imm-wormhole-uninit-impl-upgrade-selfdestruct"
    HELP = "Bridge/guardian contract exposes a delegatecall-based upgrade entrypoint (submitContractUpgrade) with no code-length or interface validation on the target. Combined with an uninitialized implementation this lets an attacker selfdestruct the implementation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-wormhole-uninit-impl-upgrade-selfdestruct.yaml"
    WIKI_TITLE = "Bridge contract-upgrade delegatecall without impl validation (Wormhole pattern)"
    WIKI_DESCRIPTION = "Cross-chain bridges often upgrade their own implementation via a VAA-signed message that names a new implementation address. The upgrade routine performs `delegatecall(newImpl, initializeData)` to run migration logic. If the target address is accepted without verifying (a) it has non-empty bytecode, (b) it implements a known upgrade interface, (c) it is not an EOA, and the implementation behind th"
    WIKI_EXPLOIT_SCENARIO = "Wormhole (Feb 2022): the implementation contract at 0x736... had an unguarded `initialize(address[] guardians)` from an earlier deploy bug. An attacker called `initialize` on the implementation directly, setting themselves as the sole Guardian. They then produced a valid VAA (signed by the attacker Guardian set) authorizing `submitContractUpgrade` with a newImpl pointing at a 2-byte SELFDESTRUCT p"
    WIKI_RECOMMENDATION = "Three layered fixes: (1) lock every implementation with `constructor() { _disableInitializers(); }`; (2) in every delegatecall-upgrade path, require `newImpl.code.length > 0` AND probe `IERC1822(newImpl).proxiableUUID()` before the delegatecall; (3) where possible avoid delegatecall-style upgrades e"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\binitialize\\s*\\(|Guardian|guardianSet|_guardianSet'}, {'contract.source_matches_regex': 'delegatecall\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(submitContractUpgrade|upgradeContract|submitUpgrade|applyUpgrade)$'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': 'delegatecall\\s*\\('}, {'function.body_not_contains_regex': 'extcodesize|code\\.length|isContract|supportsInterface|proxiableUUID'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-wormhole-uninit-impl-upgrade-selfdestruct: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
