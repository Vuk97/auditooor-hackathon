"""
view-aggregator-no-epoch-or-nonce-filter — generated from reference/patterns.dsl/view-aggregator-no-epoch-or-nonce-filter.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py view-aggregator-no-epoch-or-nonce-filter.yaml
Source: auditooor-R107-thegraph-OZ-L-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ViewAggregatorNoEpochOrNonceFilter(AbstractDetector):
    ARGUMENT = "view-aggregator-no-epoch-or-nonce-filter"
    HELP = "A view function aggregates per-record amounts from a stored list of pending claims / thaw requests / vouchers, gated only by a maturity-time check. Elsewhere in the contract, slash / cancel / invalidate / epoch-advance bumps a per-account nonce that semantically invalidates all prior records. The vi"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/view-aggregator-no-epoch-or-nonce-filter.yaml"
    WIKI_TITLE = "View aggregator over pending requests omits nonce/epoch filter — reports invalidated requests as claimable"
    WIKI_DESCRIPTION = "Staking and vesting contracts that support 'cancel-everything' semantics (slash, governance kill-switch, epoch reset) typically implement them by incrementing a per-account or per-pool nonce / epoch / version counter rather than physically deleting the request list. The actual `withdraw` / `claim` function checks each request's nonce against the current value and skips invalidated ones. The danger"
    WIKI_EXPLOIT_SCENARIO = "User U has 10 thaw requests pending against provider P, all matured. P misbehaves and gets slashed; the contract increments `prov.thawingNonce`, invalidating all 10 requests. U's wallet UI calls `getThawedTokens(U)` to show the redeemable balance — the buggy view returns the full 10-request total because no nonce filter is applied. U sees a non-zero balance and integrates it into a leveraged posit"
    WIKI_RECOMMENDATION = "Inside the loop, also gate the accumulation on `request.thawingNonce == owner.thawingNonce` (or the equivalent epoch / version check). Better: factor the per-record validity test (`isClaimable(request, owner)`) into a pure helper used by both the view and the state-mutating claim path, so they canno"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(thawingNonce|nonce|epoch|version|round|generation)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '(?i)^(get|view|pending|claimable|withdrawable|matured|thawed|unlocked|getAvailable|getClaimable|getMaturable)\\w*$'}, {'function.body_contains_regex': '\\bfor\\s*\\([^)]*\\)\\s*\\{'}, {'function.body_contains_regex': '\\b(?:requests?|claims?|vouchers?|tranches?|tickets?|withdrawals?|positions?)\\s*\\['}, {'function.body_contains_regex': '(?:matureAt|unlockAt|thawingUntil|releaseAt|expiryAt|claimableAt|maturity)\\s*<=\\s*block\\.timestamp'}, {'function.body_not_contains_regex': '(?:thawingNonce|nonce|epoch|version|round|generation)\\s*==\\s*'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — view-aggregator-no-epoch-or-nonce-filter: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
