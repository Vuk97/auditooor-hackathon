"""
raydium-remaining-accounts-bitmap-unverified — generated from reference/patterns.dsl/raydium-remaining-accounts-bitmap-unverified.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py raydium-remaining-accounts-bitmap-unverified.yaml
Source: auditooor-R76-immunefi-raydium-$505k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RaydiumRemainingAccountsBitmapUnverified(AbstractDetector):
    ARGUMENT = "raydium-remaining-accounts-bitmap-unverified"
    HELP = "NOT_SUBMIT_READY detector_fixture_smoke_only: instruction reads an auxiliary account from remaining_accounts without a visible pool-id equality guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/raydium-remaining-accounts-bitmap-unverified.yaml"
    WIKI_TITLE = "remaining_accounts bitmap/extension account not verified against pool_state"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: Anchor-style Solana programs commonly receive optional/variable accounts via `remaining_accounts`. When one of these is a pool-scoped resource, the program should assert that the resource's stored pool-id equals the declared pool's key. This row only proves the local source shape and remains NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "Illustrative only: a handler can read `remaining_accounts[0]` or `remaining_accounts.get(0)` and proceed without comparing the auxiliary account against `ctx.accounts.pool_state.key()`. The row is not corpus-backed and should not be promoted on fixture smoke alone."
    WIKI_RECOMMENDATION = "For every account passed via remaining_accounts, deserialize its stored pool-id and `require_keys_eq!(aux.pool_id, ctx.accounts.pool_state.key())`. Prefer declared `Account<>` constraints over remaining_accounts whenever the schema is known, and keep this row NOT_SUBMIT_READY until corpus-backed evidence exists."

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)anchor_lang|remaining_accounts|pool_id|TickArrayBitmapExtension|increase_liquidity|decrease_liquidity|open_position|swap'}]
    _MATCH = [{'function.kind': 'anchor_instruction'}, {'function.name_matches': '(?i)increase_liquidity|decrease_liquidity|swap|open_position|init_[A-Za-z0-9_]+'}, {'function.body_contains_regex': '(?i)ctx\\.remaining_accounts\\s*\\[\\s*\\d+\\s*\\]|remaining_accounts\\s*\\.\\s*get\\('}, {'function.body_not_contains_regex': '(?i)require_keys_eq|anchor_lang::prelude::require\\s*!\\s*\\([^)]*pool_id|assert_eq!\\s*\\([^)]*pool_id|\\.pool_id\\s*==\\s*pool_state\\.key\\(\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — raydium-remaining-accounts-bitmap-unverified: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
