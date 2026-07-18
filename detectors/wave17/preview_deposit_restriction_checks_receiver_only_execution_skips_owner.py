"""
preview-deposit-restriction-checks-receiver-only-execution-skips-owner — generated from reference/patterns.dsl/preview-deposit-restriction-checks-receiver-only-execution-skips-owner.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py preview-deposit-restriction-checks-receiver-only-execution-skips-owner.yaml
Source: r106-centrifuge-v3-SyncManager.deposit/maxMint
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PreviewDepositRestrictionChecksReceiverOnlyExecutionSkipsOwner(AbstractDetector):
    ARGUMENT = "preview-deposit-restriction-checks-receiver-only-execution-skips-owner"
    HELP = "Sync ERC-4626/7575 deposit checks `maxMint(vault, owner)` (which only validates the receiving-side restriction) at preview time, then executes `_issueShares(vault, shares, receiver, ...)` without re-checking restrictions for either `owner` (from-side) or `receiver` at execution. A frozen owner can s"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/preview-deposit-restriction-checks-receiver-only-execution-skips-owner.yaml"
    WIKI_TITLE = "Sync deposit restriction check uses owner at preview, receiver at execution — owner re-check missing"
    WIKI_DESCRIPTION = "ERC-4626 / ERC-7575 sync deposit paths take both `owner` (the source of assets) and `receiver` (the share recipient). View functions like `maxDeposit(vault, owner)` check `_canTransfer(vault, address(0), owner, ...)` which validates the to-side memberlist on the OWNER address. The deposit / mint state-changing entry then calls `_issueShares(vault, shares, receiver, ...)` and never re-checks the re"
    WIKI_EXPLOIT_SCENARIO = "Sanctioned user O is added to the freeze list. The vault's `_canTransfer(v, address(0), O, x)` returns false on the receiving-side check, so O cannot deposit into shares for themselves. O calls `vault.deposit(v, 100, R, O)` where R is a clean address O controls. Pre-flight `maxDeposit(v, O)` returns 0 (O is frozen). But many vaults guard with `>= assets` — if the helper computes `maxDeposit` again"
    WIKI_RECOMMENDATION = "At execution time, re-invoke the restriction hook against BOTH `owner` (from-side) and `receiver` (to-side): `require(_canTransfer(v, owner, receiver, shares) && _canTransfer(v, address(0), receiver, shares))`. Symmetric pattern: every sync deposit/mint must verify both endpoints at the latest possi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(sync|deposit|mint|preview|max)\\w*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(deposit|mint)\\w*'}, {'function.has_param_name_matching': '(?i)^(receiver|owner)$'}, {'function.body_contains_regex': 'require\\s*\\(\\s*max(?:Deposit|Mint)\\s*\\([^)]*\\)\\s*[<>=]'}, {'function.body_contains_regex': '\\.\\s*(?:mint|issueShares|withdraw|transfer)\\s*\\(\\s*receiver\\b'}, {'function.body_not_contains_regex': '_canTransfer\\s*\\([^)]*,\\s*owner\\s*,\\s*receiver|_canTransfer\\s*\\([^)]*,\\s*address\\s*\\(\\s*0\\s*\\)\\s*,\\s*receiver'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — preview-deposit-restriction-checks-receiver-only-execution-skips-owner: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
