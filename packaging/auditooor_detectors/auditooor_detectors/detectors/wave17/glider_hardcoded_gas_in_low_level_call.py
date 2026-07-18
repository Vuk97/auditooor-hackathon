"""
glider-hardcoded-gas-in-low-level-call — generated from reference/patterns.dsl/glider-hardcoded-gas-in-low-level-call.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-hardcoded-gas-in-low-level-call.yaml
Source: hexens-glider/hardcoded-gas-amount-in-low-level-calls
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderHardcodedGasInLowLevelCall(AbstractDetector):
    ARGUMENT = "glider-hardcoded-gas-in-low-level-call"
    HELP = "Native-ETH transfer uses `.transfer` / `.send` (hardcoded 2300 gas) or `.call{gas: N}` with a literal. Smart-wallet recipients (Safe, Argent) need more than 2300 gas on their fallback; the call will revert. Gas costs of opcodes change across hard forks (EIP-2929) — hardcoded stipends silently break."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-hardcoded-gas-in-low-level-call.yaml"
    WIKI_TITLE = "Hardcoded gas amount in low-level call — 2300 stipend breaks smart wallets"
    WIKI_DESCRIPTION = "`.transfer` and `.send` forward exactly 2300 gas. Any recipient whose fallback does storage writes or external calls (Gnosis Safe, Argent, many ERC-1271 signers) needs more and will revert. Even for EOAs, EIP-2929 (Berlin) raised `SLOAD` costs and broke contracts that hardcoded gas near the limit. `.call{gas: N}(...)` with a literal `N` has the same problem: the amount was calibrated against a spe"
    WIKI_EXPLOIT_SCENARIO = "User withdraws 1 ETH to their Gnosis Safe. The vault calls `safe.transfer(1 ether)`. Safe's fallback does ERC-1271 signature bookkeeping, consuming ~3000 gas. The call reverts with out-of-gas inside the 2300-gas stipend — the withdrawal is blocked, ETH is stuck in the vault, user has no recourse. Same pattern affects rebates, refunds, and reward claims. Amplified in post-Berlin forks where SLOAD w"
    WIKI_RECOMMENDATION = "Replace `.transfer` / `.send` with `(bool ok, ) = to.call{value: amount}(\"\"); require(ok, \"eth send failed\");`. If you need gas-limited calls (untrusted recipient), use an explicit re-entrancy guard and forward a generous amount (`gas: 30_000+`) rather than the 2300 stipend. For complex flows, u"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.call\\s*\\{|\\.transfer\\s*\\(|\\.send\\s*\\('}]
    _MATCH = [{'function.kind': 'any'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*gas\\s*:\\s*[0-9]+\\s*\\}|\\.transfer\\s*\\(|\\.send\\s*\\('}, {'function.body_not_contains_regex': '\\.call\\s*\\{\\s*value\\s*:[^}]+\\}\\s*\\(\\s*""\\s*\\)|safeTransferETH|SafeTransferLib\\.'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-hardcoded-gas-in-low-level-call: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
