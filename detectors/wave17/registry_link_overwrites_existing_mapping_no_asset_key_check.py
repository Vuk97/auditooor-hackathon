"""
registry-link-overwrites-existing-mapping-no-asset-key-check — generated from reference/patterns.dsl/registry-link-overwrites-existing-mapping-no-asset-key-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py registry-link-overwrites-existing-mapping-no-asset-key-check.yaml
Source: r106-centrifuge-v3-VaultRegistry.linkVault
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RegistryLinkOverwritesExistingMappingNoAssetKeyCheck(AbstractDetector):
    ARGUMENT = "registry-link-overwrites-existing-mapping-no-asset-key-check"
    HELP = "Linker-style registry checks `!targetDetails[target].isLinked` but writes to a composite-key mapping `mapping[parent][child][asset][manager]` without verifying the slot was empty. Two distinct targets pointing at the same key both pass the boolean check; the second write silently overwrites the firs"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/registry-link-overwrites-existing-mapping-no-asset-key-check.yaml"
    WIKI_TITLE = "Registry link gated only by per-target boolean — composite slot silently overwritten"
    WIKI_DESCRIPTION = "A composite-key registry stores one canonical address per `(parent, child, asset, manager)` slot, and remembers per-target metadata in a separate `mapping(target => Details)`. The link function checks `!Details[target].isLinked` (asymmetric guard) and writes the slot, but never reads the slot first. When two target contracts are deployed with the same `(parent, child, asset, manager)` association,"
    WIKI_EXPLOIT_SCENARIO = "Pool admin deploys VaultA at `linkVault(P,S,A,VaultA)`. Slot is set; `vaultDetails[A].isLinked = true`. A new manager deploys VaultB and calls `linkVault(P,S,A,VaultB)`. The check `!vaultDetails[B].isLinked` passes (B is new). The composite-key mapping silently overwrites VaultA. Users redeeming through `requestRedeem` now route into VaultB; VaultA's pending requests + escrowed shares are stranded"
    WIKI_RECOMMENDATION = "Add `require(targetMapping[parent][child][asset][manager] == address(0), AlreadyOccupied())` BEFORE writing the slot. Alternatively gate the link function with a symmetric per-key boolean (`mapping(parentId => mapping(...) => bool) public slotOccupied`). Audit every multi-key registry whose uniquene"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(registry|router|registrar|linker|directory|book)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(link|register|set|add|attach|bind)\\w*'}, {'function.body_contains_regex': 'require\\s*\\(\\s*!\\s*[^,]+\\.\\s*\\w*[Ll]inked\\s*[,)]'}, {'function.body_contains_regex': '\\w+\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\](?:\\s*\\[\\s*\\w+\\s*\\])?\\s*=\\s*\\w+_?\\s*;'}, {'function.body_not_contains_regex': 'require\\s*\\([^,]*\\w+\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\][^,]*==[^,]*\\b0\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — registry-link-overwrites-existing-mapping-no-asset-key-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
