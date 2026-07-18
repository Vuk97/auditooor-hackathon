"""
erc7540-claim-uses-stale-price-per-share — generated from reference/patterns.dsl/erc7540-claim-uses-stale-price-per-share.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc7540-claim-uses-stale-price-per-share.yaml
Source: auditooor-R75-spearbit-centrifuge-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc7540ClaimUsesStalePricePerShare(AbstractDetector):
    ARGUMENT = "erc7540-claim-uses-stale-price-per-share"
    HELP = "ERC-7540 claim() reads live price-per-share instead of the rate snapshotted at fulfillment. Lets claimers pick a favourable NAV print post-hoc and extract value from the vault / other depositors."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc7540-claim-uses-stale-price-per-share.yaml"
    WIKI_TITLE = "Async vault claim uses live NAV instead of fulfillment snapshot"
    WIKI_DESCRIPTION = "An ERC-7540-style async vault implements the two-phase flow (requestDeposit/requestRedeem + claim) but the claim path reads the current price-per-share via `convertToShares` / `convertToAssets` / an oracle helper. The fulfillment step was intended to freeze the exchange rate for the requester; by re-reading live price at claim time, the vault re-exposes the user to NAV movement that they no longer"
    WIKI_EXPLOIT_SCENARIO = "Alice requests to redeem 100 shares. Operator fulfills at NAV=$1.00, so the request record now holds `claimable = 100 assets`. Before Alice calls claim, NAV drops to $0.90 due to a loss event. The vault's claim() calls `convertToAssets(100)` live, returning 90 assets; Alice declines to claim. NAV recovers to $1.05; Alice claims and receives 105 assets. She has extracted 5 assets of upside she was "
    WIKI_RECOMMENDATION = "At fulfillment time, write the exact asset or share amount the requester is entitled to into the request record. In claim(), transfer *that stored amount* — never re-convert. Treat the request struct as the single source of truth for the settlement price. Add an invariant test: sum of pending `claim"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'requestDeposit|requestRedeem|pendingDepositRequest|pendingRedeemRequest|claimableDepositRequest|claimableRedeemRequest'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(claim|claimDeposit|claimRedeem|mint|withdraw|deposit|redeem)$'}, {'function.body_contains_regex': 'convertToShares\\s*\\(|convertToAssets\\s*\\(|pricePerShare\\s*\\(|getRate\\s*\\(|_sharePrice\\s*\\('}, {'function.body_not_contains_regex': 'claimable|fulfilled|settledPrice|snapshotPrice|request\\.price|pending\\.rate'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc7540-claim-uses-stale-price-per-share: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
