"""
certora-erc4626-preview-matches-mutating — generated from reference/patterns.dsl/certora-erc4626-preview-matches-mutating.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-erc4626-preview-matches-mutating.yaml
Source: certora-examples/ERC4626/previewMatchesMutating
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraErc4626PreviewMatchesMutating(AbstractDetector):
    ARGUMENT = "certora-erc4626-preview-matches-mutating"
    HELP = "ERC-4626 `preview*` function does not reflect the same accrual / fee / rounding logic the mutating variant uses — `previewMatchesMutating` Certora invariant violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-erc4626-preview-matches-mutating.yaml"
    WIKI_TITLE = "ERC-4626 preview* diverges from mutating variant (stale accrual, wrong rounding)"
    WIKI_DESCRIPTION = "Certora's ERC-4626 spec proves `previewDeposit(a) == deposit(a, msg.sender)` return-value equality (and analogues for mint/withdraw/redeem). Achieving this requires the preview function to reflect the exact same math the mutating function does: same rounding direction, same fee application, same up-to-date state. A preview that skips `accrueInterest()` / `syncFees()` or that uses `mulDiv` up vs `m"
    WIKI_EXPLOIT_SCENARIO = "Vault accrues fees once per day. `previewDeposit` reads stale `totalAssets()`, returning shares at yesterday's NAV. Aggregator quotes the user 100 shares, user signs, `deposit` runs accrual first and mints only 97. Difference pocketed by the vault / later depositors. An attacker spams preview quotes right before an accrual-jump to front-run integrators."
    WIKI_RECOMMENDATION = "Preview functions must call the same accrual / sync path the mutating variant does (or document it as a pure function of last-synced state and refuse to mutate state after). Use identical `mulDiv` rounding directions. Prove `previewMatchesMutating` with Certora or a Foundry invariant per each {depos"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)^(preview(Deposit|Mint|Withdraw|Redeem))$'}, {'contract.has_function_matching': '(?i)^(deposit|mint|withdraw|redeem)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^preview(Deposit|Mint|Withdraw|Redeem)$'}, {'function.state_mutability': 'view'}, {'function.body_not_contains_regex': '(?i)(accrueInterest|_accrue|syncFees|_syncFees|updateState|totalAssets\\(\\)|convertToShares|convertToAssets|mulDiv)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-erc4626-preview-matches-mutating: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
