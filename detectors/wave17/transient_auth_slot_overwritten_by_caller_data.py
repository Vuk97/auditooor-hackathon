"""
transient-auth-slot-overwritten-by-caller-data — generated from reference/patterns.dsl/transient-auth-slot-overwritten-by-caller-data.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transient-auth-slot-overwritten-by-caller-data.yaml
Source: defimon-eos-mine-r97/SIR_2025-03-30_post-717 ($355K SIR.trading)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TransientAuthSlotOverwrittenByCallerData(AbstractDetector):
    ARGUMENT = "transient-auth-slot-overwritten-by-caller-data"
    HELP = "Function uses tload(SLOT) to authenticate msg.sender, then writes attacker-influenced data via tstore(SAME_SLOT, ...) in the same body. A subsequent re-entry from a vanity-bruteforced or stored address passes the auth check, letting the caller bypass pool-only restrictions."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transient-auth-slot-overwritten-by-caller-data.yaml"
    WIKI_TITLE = "Transient-storage auth slot overwritten by caller-controlled data within same function"
    WIKI_DESCRIPTION = "Pool-callback functions (Uniswap V3 / Pancake V3 / Algebra) often store the expected pool address in transient storage at unlock time and check `msg.sender == tload(SLOT)` inside the callback. A vulnerable variant subsequently writes a caller-supplied integer or address back into the same SLOT via tstore — typically to forward state to a nested call. Because transient storage persists across the r"
    WIKI_EXPLOIT_SCENARIO = "SIR.trading (March 2025, $355K, Ethereum). Vault.uniswapV3SwapCallback loaded `pool = tload(0x1)`, required `msg.sender == pool`, then at the end of execution stored `amount` back via `tstore(0x1, amount)` to forward state. Attacker bruteforced a CREATE2 vanity address `0x00000000001271551295307acc16ba1e7e0d4281` (= 95759995883742311247042417521410689 as uint), deployed an exploit contract at that"
    WIKI_RECOMMENDATION = "Use distinct slots for auth-state vs forward-state, OR clear the auth slot back to zero before any tstore that places caller-controlled data. Prefer a struct in transient storage where each field has an explicit slot derived via keccak256 from a fixed namespace, and never let user-supplied amounts/a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)tload|tstore|transient'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?i)tload\\s*\\(|assembly\\s*\\{[^}]*tload'}, {'function.body_contains_regex': '(?i)tstore\\s*\\(|assembly\\s*\\{[^}]*tstore'}, {'function.name_matches': '(?i)Callback|onSwap|onMint|onFlash|deposit|swap|mint|burn|provide|withdraw|flash|exec|callback'}, {'function.body_not_contains_regex': '(?i)tstore\\s*\\(\\s*[^,]+,\\s*0\\s*\\)|tstore\\s*\\(\\s*0x0\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — transient-auth-slot-overwritten-by-caller-data: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
