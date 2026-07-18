"""
hyperevm-vault-equity-locked-until-not-checked — generated from reference/patterns.dsl/hyperevm-vault-equity-locked-until-not-checked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-vault-equity-locked-until-not-checked.yaml
Source: monetrix-c4-2026-04-precompile-reader
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmVaultEquityLockedUntilNotChecked(AbstractDetector):
    ARGUMENT = "hyperevm-vault-equity-locked-until-not-checked"
    HELP = "HyperCore VAULT_EQUITY precompile (0x802) returns (equity, lockedUntil). Issuing a CoreWriter vault-withdraw before `block.timestamp * 1000 >= lockedUntil` silently no-ops on L1 — the EVM accounting drifts from L1 truth on every premature withdraw."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-vault-equity-locked-until-not-checked.yaml"
    WIKI_TITLE = "HLP / core-vault withdraw issued without lockedUntil check (silent L1 drop)"
    WIKI_DESCRIPTION = "Hyperliquid's HLP and user-defined core-vaults enforce a withdrawal lock window (HLP is 4 days; arbitrary user-vaults can be longer). Lock state is exposed via precompile 0x802 (VAULT_EQUITY) which returns `(uint64 equity, uint64 lockedUntil)` — `lockedUntil` is an L1 timestamp in MILLISECONDS. A premature CoreWriter vault-transfer with `deposit=false` (withdrawal action) does NOT revert on L1 — t"
    WIKI_EXPLOIT_SCENARIO = "Vault has 1M USDC equity in HLP, `lockedUntil = (block.timestamp + 1 hour) * 1000`. Operator (or user, if entrypoint is permissionless) calls `withdrawFromHlp(500_000)`. The function reads `vaultEquity` purely to verify `equity >= 500_000`, ignores `lockedUntil`, then issues `sendVaultWithdraw(HLP_VAULT, 500_000)`. L1 sees the action, sees the lock still active, drops the action silently. EVM-side"
    WIKI_RECOMMENDATION = "Before issuing any CoreWriter vault-withdraw, read the current `lockedUntil` and gate: `VaultEquity memory eq = PrecompileReader.vaultEquity(account, vault); require(uint64(block.timestamp * 1000) >= eq.lockedUntil, \"vault locked\");`. Treat `lockedUntil` as authoritative — do NOT rely on cached EV"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'vaultEquity|VaultEquity|HLP|hlpVault|HLP_VAULT|sendVaultWithdraw|withdrawFromHlp|withdrawHlp|core[_]?vault|coreVault'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'vaultEquity\\s*\\(|VaultEquity\\s+memory|sendVaultWithdraw\\s*\\(|withdrawHlp|withdrawFromHlp|ACTION_VAULT_TRANSFER[^;]*\\bfalse\\b|VAULT_TRANSFER[^;]*\\bfalse\\b'}, {'function.body_not_contains_regex': 'lockedUntil|lock_until|lockEnd|lockTimestamp|unlockTime|withdrawableAfter|block\\.timestamp\\s*\\*\\s*1000\\s*>=|block\\.timestamp\\s*\\*\\s*1e3\\s*>=|require\\s*\\(\\s*(?:[a-zA-Z_]+\\.)?lockedUntil|require\\s*\\(\\s*block\\.timestamp\\s*[><]=?\\s*(?:[a-zA-Z_]+\\.)?lockedUntil'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hyperevm-vault-equity-locked-until-not-checked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
