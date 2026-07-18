"""
setwrapper-leaves-stale-canonical-to-adopted-mapping — generated from reference/patterns.dsl/setwrapper-leaves-stale-canonical-to-adopted-mapping.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py setwrapper-leaves-stale-canonical-to-adopted-mapping.yaml
Source: lisa-mine-r99-case-08806-c4-connext-2022-06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SetwrapperLeavesStaleCanonicalToAdoptedMapping(AbstractDetector):
    ARGUMENT = "setwrapper-leaves-stale-canonical-to-adopted-mapping"
    HELP = "Admin updates the wrapper / adopted-asset pointer (`s.wrapper = newWrapper`) without iterating existing `canonicalToAdopted[id]` entries that pointed at the old wrapper. Existing canonical assets keep resolving to the stale wrapper address; new flows go through the new wrapper. The two coexist silen"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/setwrapper-leaves-stale-canonical-to-adopted-mapping.yaml"
    WIKI_TITLE = "setWrapper updates wrapper pointer but leaves stale canonicalToAdopted mapping"
    WIKI_DESCRIPTION = "Pattern fires on admin functions named `setWrapper` / `updateWrapper` / `changeWrapper` whose body assigns a new wrapper / adopted-asset pointer (`s.wrapper = newWrapper;` or `wrapperOf = ...;`) WITHOUT also updating any `canonicalToAdopted[<id>]` (or `adoptedToCanonical`) mapping entries that were populated by an earlier `setupAsset` call. The two views of the wrapper diverge: high-level entry po"
    WIKI_EXPLOIT_SCENARIO = "Connext deploys with `Wrapper X` for native ETH on a canonical id. Cross-domain calls write `canonicalToAdopted[CANON_ID] = WrapperX`. Months later admin discovers a bug in `WrapperX`, deploys `WrapperY`, calls `setWrapper(WrapperY)` — `s.wrapper = WrapperY`. New cross-domain calls receive WrapperY tokens; existing positions and routes that look up by canonical id still get WrapperX. Two pools of "
    WIKI_RECOMMENDATION = "In `setWrapper` (and any wrapper-change path), iterate every canonical id that previously mapped to the old wrapper and update `canonicalToAdopted[id]` to the new wrapper. If the asset registry is large, expose an admin-callable `migrateCanonicalToAdopted(uint256[] ids)` and emit `CanonicalRemapped("

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'canonicalToAdopted|adoptedToCanonical|wrapperOf|tokenWrapper'}, {'contract.has_function_matching': 'setWrapper|updateWrapper|changeWrapper'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(setWrapper|updateWrapper|changeWrapper|setAdopted)$'}, {'function.body_contains_regex': '\\b(wrapper|adopted)\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*\\s*;|s\\.\\w*[Ww]rapper\\w*\\s*=|s\\.\\w*[Aa]dopted\\w*\\s*='}, {'function.body_not_contains_regex': '\\bcanonicalToAdopted\\s*\\[[^\\]]+\\]\\s*=\\s*|adoptedToCanonical\\s*\\[[^\\]]+\\]\\s*=\\s*|updateMapping|reinstall|migrate.*canonicals'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — setwrapper-leaves-stale-canonical-to-adopted-mapping: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
