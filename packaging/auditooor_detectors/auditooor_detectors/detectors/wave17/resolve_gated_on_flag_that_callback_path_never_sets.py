"""
resolve-gated-on-flag-that-callback-path-never-sets — generated from reference/patterns.dsl/resolve-gated-on-flag-that-callback-path-never-sets.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py resolve-gated-on-flag-that-callback-path-never-sets.yaml
Source: polymarket-drafts-1-2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ResolveGatedOnFlagThatCallbackPathNeverSets(AbstractDetector):
    ARGUMENT = "resolve-gated-on-flag-that-callback-path-never-sets"
    HELP = "External resolve/finalize/settle gates refund on a flag that the function never sets — desync with the upstream callback path strands the creator's reward (Polymarket Drafts 1 + 2)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/resolve-gated-on-flag-that-callback-path-never-sets.yaml"
    WIKI_TITLE = "Resolve / finalize entrypoint gates refund on a flag the callback path never sets — multi-hop refund desync"
    WIKI_DESCRIPTION = "An external resolution entrypoint (resolveManually / resolve / finalize / settle) on an adapter/oracle/market contract gates the creator refund on a `refund` storage flag that the function itself never writes. If any permissionless callback path reaches the same question without flipping `refund = true`, the gate here is silently skipped and the refund never happens. Heuristic / MEDIUM confidence:"
    WIKI_EXPLOIT_SCENARIO = "Polymarket UmaCtfAdapter.resolveManually (src/v1/uma/UmaCtfAdapter.sol:267) gates the refund on `if (questionData.refund) _refund(questionData);`. The companion `priceDisputed` callback ends in `_reset(address(this), questionID, false, questionData);` whose `resetRefund=false` branch never sets `refund = true`. After any third-party dispute on a flagged market, admin `resolveManually` runs without"
    WIKI_RECOMMENDATION = "Either (a) fold the flag-set into the upstream callback so the read-side gate here is always reached with the correct flag value (preferred — see sibling pattern's recommendation), or (b) replace the flag-gate with a direct `if (rewardToken.balanceOf(address(this)) >= reward) _refund(...);` balance "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Adapter|Oracle|Uma|Resolve|Dispute|Request|Optimistic)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(resolveManually|resolve|finalize|settle)'}, {'function.body_contains_regex': 'if\\s*\\(\\s*\\w*\\.?refund\\s*\\)'}, {'function.body_not_contains_regex': '(?:questionData\\.)?refund\\s*=\\s*true'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — resolve-gated-on-flag-that-callback-path-never-sets: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
