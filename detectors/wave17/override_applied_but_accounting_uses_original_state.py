"""
override-applied-but-accounting-uses-original-state - generated from reference/patterns.dsl/override-applied-but-accounting-uses-original-state.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py override-applied-but-accounting-uses-original-state.yaml
Source: lane-a3-cross-language-rust-to-solidity-state-accounting-drift
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OverrideAppliedButAccountingUsesOriginalState(AbstractDetector):
    ARGUMENT = "override-applied-but-accounting-uses-original-state"
    HELP = "Function applies an override or version update, then computes accounting from the original snapshot instead of the refreshed active state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/override-applied-but-accounting-uses-original-state.yaml"
    WIKI_TITLE = "Override path updates live state but accounting still uses the original snapshot"
    WIKI_DESCRIPTION = "A multi-step update or finalize path snapshots a campaign/config struct, mutates live storage with an override or new version, and later computes remaining budget, payout, refund, or debt from the stale original snapshot. Because the local snapshot no longer matches the active state, accounting drifts from what storage now says is live."
    WIKI_EXPLOIT_SCENARIO = "Campaign 7 starts with rate = 1, spent = 10, budget = 1000. `overrideCampaignAndFinalize(7, 3, 50)` snapshots `originalCampaign = campaigns[7]`, then writes `campaigns[7].rate = 3` and increments spent. The finalize math still uses `originalCampaign.rate` and `originalCampaign.spent`, undercharging or overcharging by the stale pre-override values."
    WIKI_RECOMMENDATION = "After any override, version bump, or active-state rewrite, refresh the local struct from storage before computing accounting. Prefer a single `activeCampaign` snapshot taken after all writes, or compute directly from the live storage slot."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(campaign|config|version|override|budget|spent|rate|current|latest|active|cache)'}, {'contract.has_function_matching': '(?i)(override|update|replace|activate|finalize|settle|campaign)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(override|update|replace|activate|finalize|settle|close|complete|process|campaign)'}, {'function.body_ordered_regex': {'first': '(?i)\\b[A-Z][A-Za-z0-9_]*\\s+(?:memory|storage)\\s+(?:original|snapshot|cached|base|prior|old)\\w*\\s*=\\s*\\w+\\s*\\[[^]]+\\]', 'second': '(?is)(?:\\w+\\s*\\[[^]]+\\]\\s*\\.\\s*(?:version|rate|spent|budget|amount|total|remaining)\\s*(?:=|\\+=|-=)|(?:override|update|replace|activate|finalize|settle)\\w*\\s*\\([^;]{0,200}\\))[\\s\\S]{0,600}(?:remaining|reward|refund|payout|claimable|amount|budget|spent|used|total|debt|credit)\\w*\\s*=\\s*[^;]{0,220}\\b(?:original|snapshot|cached|base|prior|old)\\w*\\.', 'ignore_comments_and_strings': True}}, {'function.body_contains_regex': '(?i)(campaign|override|version|budget|spent|rate|remaining|reward|refund|payout|claimable)'}, {'function.body_not_contains_regex': '(?is)\\b[A-Z][A-Za-z0-9_]*\\s+(?:memory|storage)\\s+(?:latest|current|active|fresh)\\w*\\s*=\\s*\\w+\\s*\\[[^]]+\\][\\s\\S]{0,260}(?:remaining|reward|refund|payout|claimable|amount|budget|spent|used|total|debt|credit)\\w*\\s*=\\s*[^;]{0,220}\\b(?:latest|current|active|fresh)\\w*\\.'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - override-applied-but-accounting-uses-original-state: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
