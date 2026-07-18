"""
dh-pre-approval-drained-via-deterministic-address — generated from reference/patterns.dsl/dh-pre-approval-drained-via-deterministic-address.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-pre-approval-drained-via-deterministic-address.yaml
Source: defihacklabs-2026-03/Venus_THE
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhPreApprovalDrainedViaDeterministicAddress(AbstractDetector):
    ARGUMENT = "dh-pre-approval-drained-via-deterministic-address"
    HELP = "Public wrapper calls ERC20 transferFrom with a caller-controlled `from` parameter. If users pre-approved a deterministic address (CREATE2), attacker deploys the attack contract at that address and sweeps every pre-approval in one tx."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-pre-approval-drained-via-deterministic-address.yaml"
    WIKI_TITLE = "transferFrom(from, ...) with unchecked from — mass pre-approval drain"
    WIKI_DESCRIPTION = "Several 2025-2026 exploits (Venus_THE, Kame 2025-09) weaponized the same primitive: a contract or frontend announces a future deployment address. Users approve that address. The deployed contract then exposes a function that passes its own `from` parameter into ERC20.transferFrom, pulling approved balances from every user that pre-approved the address."
    WIKI_EXPLOIT_SCENARIO = "Protocol front-end instructs users to approve(attackAddr) for upcoming airdrop. Attacker deploys a contract at attackAddr that calls token.transferFrom(victim, attacker, allowance) — draining every victim who pre-approved."
    WIKI_RECOMMENDATION = "Never expose a wrapper that lets the caller choose `from`. If a router pattern is required, require from == msg.sender, or require an authenticated signature from `from` per-call (not just a standing allowance)."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'transferFrom|safeTransferFrom'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.body_contains_regex': 'transferFrom\\s*\\(\\s*[^,]+,\\s*[^,]+,'}, {'function.has_param_of_type': 'address'}, {'function.has_param_name_matching': 'from|src|sender|victim'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*from|require\\s*\\(.*allowance'}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-pre-approval-drained-via-deterministic-address: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
