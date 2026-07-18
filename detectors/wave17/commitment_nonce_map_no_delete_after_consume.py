"""
commitment-nonce-map-no-delete-after-consume — generated from reference/patterns.dsl/commitment-nonce-map-no-delete-after-consume.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py commitment-nonce-map-no-delete-after-consume.yaml
Source: auditooor/SP-A1-frost-nonce-hygiene-2026-05-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CommitmentNonceMapNoDeleteAfterConsume(AbstractDetector):
    ARGUMENT = "commitment-nonce-map-no-delete-after-consume"
    HELP = "Single-use commitment/nonce/signature map is consumed in a sign/verify/ecrecover flow but not deleted afterwards — defense-in-depth gap. Without the delete, a future call path that re-enters with the same key (e.g., via reentrancy, a forgotten guard, or an upgradable contract reset) can replay the v"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/commitment-nonce-map-no-delete-after-consume.yaml"
    WIKI_TITLE = "Commitment/nonce map not deleted after consume — replay/reentrancy hygiene gap"
    WIKI_DESCRIPTION = "Single-use commitments are typically tracked in a map (e.g., `mapping(bytes32 => bool) usedCommitment` or `mapping(bytes32 => Sig) commitmentToSig`) and gated by a guard (e.g., `require(usedCommitment[c] == false)`). The defense-in-depth practice is to delete or zeroize the map entry IMMEDIATELY after the consume. Omitting the delete leaves the value live in storage; while a guarded path may still"
    WIKI_EXPLOIT_SCENARIO = "(1) Contract has `mapping(bytes32 => bool) used; mapping(bytes32 => bytes32) sigOf;`. `consume(c, sig)` requires `used[c] == false`, runs ecrecover, sets `used[c] = true` — but never deletes `sigOf[c]`. (2) An upgrade introduces a parallel-domain `consumeV2(c, sig2)` that forgets the `used` guard but reuses `sigOf`. The attacker re-submits the original commitment; `sigOf[c]` is still live; replay "
    WIKI_RECOMMENDATION = "Immediately after the consume of a single-use commitment / nonce / signature, `delete map[key]` or zeroize all related entries. This holds storage clean and prevents regression in guards from re-enabling replay. For FROST signing flows specifically, the per-key commitment-to-nonce map MUST be delete"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_declaration_matching': 'mapping\\s*\\(\\s*(bytes32|uint256|address)\\s*=>\\s*(bytes32|bool|uint256|struct)'}, {'contract.has_state_var_matching': '(commitment|nonce|signature|digest|hash)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(sign|verify|consume|claim|redeem|finalize|settle|process|execute|complete)'}, {'function.body_contains_regex': '(commitment|nonce|signature|digest|hash)\\s*\\[\\s*\\w+\\s*\\]'}, {'function.body_contains_regex': '(ecrecover|sign|verify|recoverAddr|recoverSigner|recover\\s*\\()'}, {'function.body_not_contains_regex': '(delete\\s+(commitment|nonce|signature|digest|hash)\\s*\\[|=\\s*bytes32\\s*\\(\\s*0\\s*\\)|=\\s*0\\s*;.{0,40}//\\s*zero)'}, {'function.is_mutating': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — commitment-nonce-map-no-delete-after-consume: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
