"""
redeem_zero_assets_burns_shares.py — Custom Slither detector.

Pattern (Zellic slice_aa glif-12, HIGH): an ERC-4626 redeem / withdraw
function computes a local `assets` amount from previewRedeem / convertToAssets
(often capped by `liquidAssets` via min), then unconditionally calls
`_burn(user, shares)`. When the preview result exceeds available liquidity
and the min caps it to 0 (or the preview itself rounds to 0), the burn still
runs — the caller loses shares for nothing.

Detection strategy:
    1. Walk user functions whose name is redeem / withdraw / withdrawTo /
       redeemShares.
    2. Confirm the function internally calls a helper named previewRedeem /
       convertToAssets / previewWithdraw (InternalCall or HighLevelCall).
    3. Confirm the function internally calls _burn / burn (InternalCall
       or HighLevelCall whose callee name matches).
    4. Confirm the function does NOT contain an assertion / require / IF
       guard that revert-paths on a zero assets value before the burn.
       Approximation: walk nodes in CFG order. For every node before the
       burn call, look for require_or_assert nodes whose local_variables_read
       includes a variable whose name contains "asset" (the `assets` local).
       If no such guard exists → flag.

@author auditooor wave8
@pattern slice_aa glif-12
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
from slither.slithir.operations import InternalCall, HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_REDEEM_FN_NAMES = frozenset({"redeem", "withdraw", "withdrawto", "redeemshares", "redeemfor"})
_PREVIEW_HINTS = ("previewredeem", "previewwithdraw", "converttoassets", "sharestoassets")
_BURN_HINTS = ("_burn", "burn", "burnshares", "_burnshares")


def _call_name(ir) -> str:
    fn = getattr(ir, "function", None)
    if fn is None:
        return ""
    return (getattr(fn, "name", "") or "").lower()


def _function_has_preview(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, (InternalCall, HighLevelCall)):
                name = _call_name(ir)
                if any(h in name for h in _PREVIEW_HINTS):
                    return True
    return False


def _burn_call_index(function):
    """Return (idx, node) of the first burn call in the function, or (None, None)."""
    for idx, node in enumerate(function.nodes):
        for ir in node.irs:
            if isinstance(ir, (InternalCall, HighLevelCall)):
                name = _call_name(ir)
                # Match only exact burn-like names to avoid _burnFee, etc.
                if name in ("_burn", "burn", "_burnshares", "burnshares"):
                    return idx, node
    return None, None


def _has_asset_guard_before(function, burn_idx: int) -> bool:
    """
    Return True if any node at index < burn_idx is a require/assert OR an IF
    that reads a local variable whose name contains 'asset'. This approximates
    `require(assets > 0)` / `if (assets == 0) revert`.
    """
    for idx in range(burn_idx):
        node = function.nodes[idx]
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue
        for v in node.local_variables_read:
            nm = (getattr(v, "name", "") or "").lower()
            if "asset" in nm:
                return True
    return False


class RedeemZeroAssetsBurnsShares(AbstractDetector):
    """Detect ERC-4626 redeem/withdraw that burns shares when computed assets == 0."""

    ARGUMENT = "redeem-zero-assets-burns-shares"
    HELP = (
        "redeem()/withdraw() burns user shares without checking that the "
        "computed assets amount is > 0 — user loses shares for zero assets"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC-4626 Redeem Burns Shares on Zero-Asset Path"
    WIKI_DESCRIPTION = (
        "An ERC-4626 vault's `redeem` / `withdraw` function computes the asset "
        "amount owed to the caller (usually from `previewRedeem` capped by "
        "available liquidity) and then unconditionally calls `_burn(user, shares)`. "
        "When the preview exceeds available liquidity (or rounds to zero) the "
        "`assets` local becomes 0, but the shares are burnt anyway — the caller "
        "loses their share balance and receives nothing. Found in glif-12 (Zellic "
        "slice_aa, HIGH)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function redeem(uint256 shares) external returns (uint256) {
    uint256 assets = min(previewRedeem(shares), liquidAssets);
    _burn(msg.sender, shares);                        // BUG: always burns
    if (assets > 0) token.transfer(msg.sender, assets);
    return assets;
}
```
Vault temporarily has no liquid assets (delegated to a yield strategy).
User calls redeem() expecting a revert; instead the function silently
runs _burn for 100% of their shares and transfers 0 tokens."""
    WIKI_RECOMMENDATION = (
        "Add `require(assets > 0, \"zero assets\")` (or revert with a custom "
        "error) immediately after computing `assets`, before the `_burn` call. "
        "Fail closed — never burn shares on a zero-asset path."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                if (function.name or "").lower() not in _REDEEM_FN_NAMES:
                    continue
                if function.visibility not in ("public", "external"):
                    continue

                if not _function_has_preview(function):
                    continue

                burn_idx, burn_node = _burn_call_index(function)
                if burn_idx is None:
                    continue

                if _has_asset_guard_before(function, burn_idx):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " computes assets from previewRedeem/convertToAssets and "
                    "then burns shares at ",
                    burn_node,
                    " without first requiring assets > 0. On a zero-asset "
                    "path the caller loses shares for nothing.\n",
                ]
                results.append(self.generate_result(info))

        return results
