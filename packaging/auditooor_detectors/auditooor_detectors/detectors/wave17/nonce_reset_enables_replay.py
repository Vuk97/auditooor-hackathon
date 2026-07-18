"""
nonce-reset-enables-replay — generated from reference/patterns.dsl/nonce-reset-enables-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nonce-reset-enables-replay.yaml
Source: solodit-cluster-nonce-reset-replay
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NonceResetEnablesReplay(AbstractDetector):
    ARGUMENT = "nonce-reset-enables-replay"
    HELP = "Admin-gated function resets a user's replay-protection nonce to zero. Any previously signed off-chain message for that user (meta-transaction, permit, order) becomes valid again and can be replayed."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nonce-reset-enables-replay.yaml"
    WIKI_TITLE = "Nonce reset enables signature replay"
    WIKI_DESCRIPTION = "The contract exposes an admin-only function that zeroes out a per-user nonce mapping (account reinit, account migration, admin reset helper). Off-chain signatures are replay-protected by a monotonically increasing nonce. Once the nonce counter is wiped back to zero, any signature the user previously broadcast at nonces 0..N-1 is valid to submit again, enabling replay of permits, meta-transactions,"
    WIKI_EXPLOIT_SCENARIO = "A user signs a meta-transaction at nonce 5 authorizing a transfer of 100 tokens. The relayer submits it, the contract increments the user's nonce to 6, and the signature is considered consumed. The protocol later migrates the account and the admin calls `resetNonce(user)`, which sets `nonces[user] = 0`. The attacker — who recorded the original signed payload off-chain — resubmits it. The signature"
    WIKI_RECOMMENDATION = "Never reset a user's replay-protection nonce to zero. If accounts genuinely must be re-initialized, either (a) bump the nonce forward past any previously-used values (monotonic-only), (b) include an epoch / version field in the EIP-712 domain separator and bump that instead of zeroing nonces, or (c)"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'nonce|nonces|_nonces|userNonce'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.writes_storage_matching': 'nonce|nonces'}, {'function.body_contains_regex': 'nonces\\[.*\\]\\s*=\\s*0|delete\\s+nonces\\[|_nonces\\[.*\\]\\s*=\\s*0|nonce\\s*=\\s*0'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — nonce-reset-enables-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
