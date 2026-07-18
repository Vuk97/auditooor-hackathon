"""
branch-asymmetric-idempotency-flag-toggled-in-only-one-arm — generated from reference/patterns.dsl/branch-asymmetric-idempotency-flag-toggled-in-only-one-arm.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py branch-asymmetric-idempotency-flag-toggled-in-only-one-arm.yaml
Source: auditooor-R108-kiln-v1-cl-dispatcher-withdrawn-flag
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BranchAsymmetricIdempotencyFlagToggledInOnlyOneArm(AbstractDetector):
    ARGUMENT = "branch-asymmetric-idempotency-flag-toggled-in-only-one-arm"
    HELP = "Function consumes a one-shot resource (exemption / fee waiver / claim) by writing an idempotency flag to true. The write lives inside ONE branch of a multi-branch `if`; another branch processes a subset of the same value WITHOUT toggling the flag. If the gating conditions later flip (e.g. balance cr"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/branch-asymmetric-idempotency-flag-toggled-in-only-one-arm.yaml"
    WIKI_TITLE = "Idempotency flag toggled in one branch but not the other — re-consumption window"
    WIKI_DESCRIPTION = "A typical pattern: `if (exitRequested && balance >= threshold && !withdrawn) { exempt the principal; stakingContract.toggleWithdrawn(); }` followed by silent fall-through for the non-matching branch. The flag's purpose is single-use exemption — but the gating includes a balance threshold AND an exit-requested flag. If a slashed validator (`exitRequested = false`) later gets restored to a healthy s"
    WIKI_EXPLOIT_SCENARIO = "Kiln-V1 ConsensusLayerFeeDispatcher.dispatch path: validator V1 is slashed at epoch 1000, exits unilaterally with balance = 28 ether (under 31 threshold, so `withdrawn` flag stays false on the dispatch path). Kiln rebates manually per T&Cs by sending 4 ether off-chain to the recipient — recipient now has 32 ether sitting in its address. The withdrawer calls `withdrawCLFee(pubKey)` which re-enters "
    WIKI_RECOMMENDATION = "Either: (a) toggle the idempotency flag in EVERY branch that processes the same one-shot value, including the fall-through / slashing path — the cleanest fix when the resource is genuinely single-use across the function's full input range; or (b) hoist the flag write to AFTER the multi-branch logic,"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.body_contains_regex': 'if\\s*\\([^{}]*!\\s*[a-zA-Z_]*(?:[wW]ithdrawn|[Cc]laimed|[Cc]onsumed|[Pp]rocessed|[Rr]edeemed|[Pp]aid|[Ss]ettled)[^{}]*\\)\\s*\\{[^{}]*?(?:toggle[A-Z][a-zA-Z]*\\s*\\(|[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*true)'}, {'function.body_contains_regex': '(?i)(?:rebate|rebated|manual|off-?chain|operator\\s+side|external\\s+process|slashing|underperform|slashed|terms\\s*&|t&c)'}, {'function.body_not_contains_regex': '\\}\\s*else\\s*\\{[^{}]*?(?:toggle[A-Z][a-zA-Z]*\\s*\\(|[a-zA-Z_][a-zA-Z0-9_]*\\s*=\\s*true)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — branch-asymmetric-idempotency-flag-toggled-in-only-one-arm: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
