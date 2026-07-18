"""
delegated-votes-overflow-uint96 — generated from reference/patterns.dsl/delegated-votes-overflow-uint96.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegated-votes-overflow-uint96.yaml
Source: solodit-cluster/cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegatedVotesOverflowUint96(AbstractDetector):
    ARGUMENT = "delegated-votes-overflow-uint96"
    HELP = "Compound-style DelegateChecker arithmetic in a governance contract uses uint96 for vote weights without SafeCast / type(uint96).max guard / supply-cap hook; token supplies above 2^96 brick delegation and voting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegated-votes-overflow-uint96.yaml"
    WIKI_TITLE = "Vote-weight arithmetic on uint96 without overflow guard — governance DoS at high supply"
    WIKI_DESCRIPTION = "A state-mutating external/public function on a contract with votes / delegatedVotes / checkpoints storage performs vote-weight arithmetic using uint96-typed identifiers (uint96 votes / delegatedVotes / weight / amount), the Compound helpers unsafe96 / _add96, or explicit (uint96) casts, and does not pair any of them with SafeCast.toUint96, a require(x <= type(uint96).max) check, a _checkMaxSupply "
    WIKI_EXPLOIT_SCENARIO = "Project T forks Compound's Comp.sol delegation code wholesale. T's token has 24 decimals (for trading-price ergonomics) and 10B total supply, so totalSupply() = 10_000_000_000e24 = 1e34, more than 100x 2^96. Alice holds 2% (2e32) and tries to delegate to Bob. The _moveDelegates helper attempts `add96(bobOld, 2e32)` — the (uint96) cast silently truncates (in an unchecked block) or reverts (in Solid"
    WIKI_RECOMMENDATION = "Replace the uint96 vote-weight slot with uint224 (or uint256 if storage layout can absorb it) to obtain the full ERC20 2^256 headroom, OR enforce a hard `require(totalSupply() <= type(uint96).max)` in the token's mint/rebase/aggregate path so vote totals can never exceed the checkpoint type. When ke"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'votes|delegatedVotes|checkpoints'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'uint96\\s*(votes|delegatedVotes|weight|amount)|unsafe96|_add96|\\(uint96\\)'}, {'function.body_not_contains_regex': 'SafeCast|safeCast|require\\s*\\(\\s*\\w+\\s*<=\\s*type\\s*\\(\\s*uint96\\s*\\)\\.max|_checkMaxSupply|maxTotalSupply|MAX_UINT96'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — delegated-votes-overflow-uint96: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
