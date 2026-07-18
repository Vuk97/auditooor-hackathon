"""
certora-makerdao-urn-art-ink-bounds — generated from reference/patterns.dsl/certora-makerdao-urn-art-ink-bounds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-makerdao-urn-art-ink-bounds.yaml
Source: certora-dss-vat/urnSafetyBounds
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraMakerdaoUrnArtInkBounds(AbstractDetector):
    ARGUMENT = "certora-makerdao-urn-art-ink-bounds"
    HELP = "Urn-modifying function writes Art/ink without the `ink*spot >= Art*rate` safety check — breaks Maker Vat solvency invariant."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-makerdao-urn-art-ink-bounds.yaml"
    WIKI_TITLE = "Urn mutator missing `ink*spot >= Art*rate` solvency guard"
    WIKI_DESCRIPTION = "Maker's Certora proof for `Vat.frob` requires that after any urn modification, either the urn is safe (`ink * spot >= Art * rate`) or the change is a pure de-risking (less debt and/or more collateral). A new `adjustUrn` path that writes ink/Art without re-running the safety check lets a user extract collateral while holding debt that was previously just-at-threshold — the urn crosses into unsafe t"
    WIKI_EXPLOIT_SCENARIO = "A governance hook `emergencyAdjust(urn, dink, dart)` exists to let privileged actors rebalance during hedge-mode. It writes `urn.ink += dink; urn.Art += dart;` and only asserts dust. A compromised keeper calls it with `dink = -90%` on a barely-safe urn, leaving Art unchanged. Next oracle tick, urn is deeply unsafe; liquidation auctions the remaining 10% of ink for 100% of Art, protocol eats the 90"
    WIKI_RECOMMENDATION = "Every urn-writing function must conclude with the Vat safety check: `require((dart <= 0 && dink >= 0) || urn.ink * ilk.spot >= urn.Art * ilk.rate)`. Reproduce Certora's `urnSafetyBounds` rule via Halmos/Certora on every new urn-touching method."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(urns|urn|Art|ink|ilks|rate|spot)'}, {'contract.source_matches_regex': '(?i)(frob|fork|grab|vat|dss)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(frob|fork|_frob|_adjustUrn|adjust|modifyPosition|_modifyCollateral)[A-Za-z0-9_]*'}, {'function.writes_storage_matching': '(?i)(urn|Art|ink|urns)'}, {'function.body_not_contains_regex': '(?i)(ink\\s*\\*\\s*spot|Art\\s*\\*\\s*rate|require[^;]*(ink|spot)[^;]*(Art|rate)|safe\\s*\\(|isSafe|_isSafe)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-makerdao-urn-art-ink-bounds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
