"""
cap_check_on_mint_only.py - Custom Slither detector.

Pattern (Vultisig maxCapPerUser, slice_aa P51): A token contract enforces a
per-user cap inside `mint(user, amount)` via
`require(balanceOf[user] + amount <= cap)`, but the same cap is NEVER
enforced inside `_update` / `_transfer` / `_beforeTokenTransfer`. A user
sitting at their cap can therefore receive additional tokens via a normal
transfer, silently bypassing the cap.

Detection strategy:
    1. Iterate every non-vendored contract that defines BOTH:
         a) a function whose lowercased name starts with "mint", and
         b) an internal/private function whose name is `_update`,
            `_transfer`, `_beforeTokenTransfer`, or `_afterTokenTransfer`.
    2. The mint function must contain a require/assert whose Binary
       comparison (LESS_EQUAL/LESS) involves any state variable whose name
       contains "cap" / "limit" / "max" - that's the cap variable.
    3. The token-update hook must NOT contain a require/assert whose Binary
       compare references that same cap state variable.
    4. If both checks hold → flag the token-update hook.

@author auditooor wave9
@pattern slice_aa P51 / Vultisig maxCapPerUser
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_HOOK_NAMES = ("_update", "_transfer", "_beforetokentransfer", "_aftertokentransfer")
_CAP_HINTS = ("cap", "limit", "max")
_LE_TYPES = frozenset({BinaryType.LESS_EQUAL, BinaryType.LESS})


def _looks_like_cap_var(sv) -> bool:
    nm = (getattr(sv, "name", "") or "").lower()
    return any(h in nm for h in _CAP_HINTS)


def _mint_cap_state_vars(function):
    """
    Return set of cap-named state vars the mint function reads inside a
    require/assert with a LESS / LESS_EQUAL compare.
    """
    caps = set()
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        cap_reads = [sv for sv in node.state_variables_read if _looks_like_cap_var(sv)]
        if not cap_reads:
            continue
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type in _LE_TYPES:
                caps.update(cap_reads)
                break
    return caps


def _hook_checks_cap(function, cap_vars) -> bool:
    """Return True if the hook contains a require/assert reading any cap var."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in _LE_TYPES and ir.type != BinaryType.GREATER_EQUAL and ir.type != BinaryType.GREATER:
                continue
            if any(sv in node.state_variables_read for sv in cap_vars):
                return True
    return False


class CapCheckOnMintOnly(AbstractDetector):
    """Flag per-user cap enforced only in mint() and not in _update/_transfer hook."""

    ARGUMENT = "cap-check-on-mint-only"
    HELP = (
        "Per-user cap enforced in mint() but NOT in _update/_transfer hook - "
        "users at the cap can receive more tokens via plain transfer"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Per-User Cap Enforced Only In Mint"
    WIKI_DESCRIPTION = (
        "A token contract enforces a per-user balance cap inside `mint(user, "
        "amount)` but never replicates the same check inside the ERC20 "
        "`_update` / `_transfer` hook. A user holding the maximum permitted "
        "balance can keep receiving more tokens through ordinary transfers, "
        "bypassing the protocol's distribution invariant. Reported in Vultisig "
        "maxCapPerUser."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function mint(address to, uint256 a) external {
    require(balanceOf[to] + a <= CAP, "cap"); // mint guard only
    _mint(to, a);
}

function _update(address from, address to, uint256 a) internal override {
    super._update(from, to, a);                // BUG: no cap check
}
```
1. Alice mints up to her CAP.
2. Bob transfers her additional tokens - `_update` doesn't check the cap.
3. Alice's balance silently grows past CAP, bypassing the distribution rule."""
    WIKI_RECOMMENDATION = (
        "Move the cap check into the `_update` / `_transfer` hook so it applies "
        "to every balance change, not only mints. Mint becomes a thin wrapper "
        "around `_mint`; the hook enforces `balanceOf[to] <= CAP` for any path."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            mint_fns = [
                f for f in contract.functions_and_modifiers_declared
                if (f.name or "").lower().startswith("mint") and not f.is_constructor
            ]
            hook_fns = [
                f for f in contract.functions_and_modifiers_declared
                if (f.name or "").lower() in _HOOK_NAMES
            ]
            if not mint_fns or not hook_fns:
                continue

            # Collect cap state vars referenced by mint guards.
            cap_vars: set = set()
            mint_with_cap = None
            for mf in mint_fns:
                caps = _mint_cap_state_vars(mf)
                if caps:
                    cap_vars |= caps
                    mint_with_cap = mf
            if not cap_vars:
                continue

            for hook in hook_fns:
                if _hook_checks_cap(hook, cap_vars):
                    continue
                info: DETECTOR_INFO = [
                    hook,
                    " does not enforce the per-user cap (",
                    mint_with_cap,
                    " checks it on mint only). Recipients can grow past the "
                    "cap via plain transfers - replicate the cap check in the hook.\n",
                ]
                results.append(self.generate_result(info))

        return results
