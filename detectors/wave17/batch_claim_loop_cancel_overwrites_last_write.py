"""
batch-claim-loop-cancel-overwrites-last-write — generated from reference/patterns.dsl/batch-claim-loop-cancel-overwrites-last-write.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py batch-claim-loop-cancel-overwrites-last-write.yaml
Source: r106-centrifuge-v3-BatchRequestManager.notifyDeposit/notifyRedeem
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BatchClaimLoopCancelOverwritesLastWrite(AbstractDetector):
    ARGUMENT = "batch-claim-loop-cancel-overwrites-last-write"
    HELP = "Batched claim loop overwrites a single `cancelled` scalar each iteration instead of accumulating. When the inner helper can surface a non-zero cancellation in more than one iteration of the same `for` loop, every cancel except the last is silently dropped — the corresponding cross-chain callback nev"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/batch-claim-loop-cancel-overwrites-last-write.yaml"
    WIKI_TITLE = "Batched claim loop drops intermediate cancellations via single-scalar overwrite"
    WIKI_DESCRIPTION = "Async vault and bridge claim drainers iterate over a per-user epoch list with a `for (i = 0; i < maxClaims; i++)` sweep. Each iteration returns a tuple `(payout, payment, cancelled, canClaimAgain)`. The outer function aggregates the payout/payment with `+=` but stores the `cancelled` slot with bare `=`. When two iterations both flag a cancellation (e.g. user cancelled in epoch N and force-cancelle"
    WIKI_EXPLOIT_SCENARIO = "Investor enqueues `cancelDepositRequest` at hub-epoch N. Hub processes other approvals so the queue advances to epoch N+5 before the cancel claims; force-cancel runs at epoch N+5. Investor calls `notifyDeposit(maxClaims=10)`. The helper returns `cancelled = X` for epoch N (queued cancel) and `cancelled = Y` for epoch N+5 (force-cancel). The outer function's `cancelledAssetAmount = cancelled` overw"
    WIKI_RECOMMENDATION = "Aggregate cancellations across iterations: replace `cancelledX = cancelled;` with `cancelledX += cancelled;`, OR break out of the loop the moment a cancellation is surfaced and process the rest in a follow-up call. If aggregating, ensure the downstream callback can carry a sum-of-cancellations paylo"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(claim|notify|fulfill|process|drain)\\w*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(notify|claim|drain|process|finalize|settle)\\w*'}, {'function.body_contains_regex': 'for\\s*\\([^)]*\\)\\s*\\{[\\s\\S]{0,500}?\\(\\s*[^,]+,\\s*[^,]+,\\s*[^,]*\\bcancel\\w*\\s*,\\s*[^)]*\\bbool\\s+\\w+\\s*\\)\\s*='}, {'function.body_contains_regex': 'if\\s*\\(\\s*\\w*cancel\\w*\\s*>\\s*0\\s*\\)\\s*\\{?\\s*\\w*[Cc]ancel\\w*\\s*='}, {'function.body_not_contains_regex': '\\w*[Cc]ancel\\w*\\s*\\+='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — batch-claim-loop-cancel-overwrites-last-write: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
