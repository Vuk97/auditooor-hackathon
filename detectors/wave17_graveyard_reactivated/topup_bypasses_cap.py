"""
topup_bypasses_cap.py - Custom Slither detector.

Pattern (Zellic slice_af Ostium, MEDIUM): a position/trade contract enforces
`maxAllowedCollateral` (or any max-size cap) in `openTrade` / `deposit`, but
a sibling `topUpCollateral` / `increaseCollateral` / `addMargin` function
increments the same collateral field without re-reading the cap. Traders
open a trade at the cap, then top up repeatedly to exceed the intended
limit.

Detection strategy:
    1. Identify contracts with at least one state variable whose name
       matches a cap hint - {"maxallowed", "maxcollateral", "maxsize",
       "cap", "limit", "maxbalance", "maxposition"}.
    2. For each function whose lowercased name matches one of the "top-up"
       families: {"topup", "increasecollat", "addmargin", "addcollat",
       "increaseposition"}:
         - It must WRITE to a state variable whose name looks like a
           collateral/position field (contains "collat"|"margin"|
           "position"|"balance"|"amount").
         - It must NOT READ the cap state variable anywhere in the function
           (no require/assert referencing the cap).
    3. Flag.

Dedup: no wave1..10 detector targets "top-up misses cap recheck". Related
but distinct: `cap_check_on_mint_only` (wave9) targets ERC20 mint caps, not
per-position collateral caps on increment paths.

@author auditooor wave11
@pattern slice_af Ostium
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_CAP_SV_HINTS = (
    "maxallowed",
    "maxcollat",
    "maxsize",
    "maxposition",
    "maxmargin",
    "maxbalance",
    "maxdeposit",
    "positioncap",
    "collateralcap",
)

_TOPUP_FN_HINTS = (
    "topup",
    "increasecollat",
    "increasemargin",
    "addmargin",
    "addcollat",
    "increaseposition",
    "depositcollat",
    "topupposition",
)

_COLLAT_SV_HINTS = (
    "collat",
    "margin",
    "position",
    "balance",
    "amount",
    "principal",
    "size",
)


def _find_cap_vars(contract):
    """Return the list of state vars whose name matches a cap hint."""
    out = []
    for sv in contract.state_variables_ordered:
        nm = (sv.name or "").lower()
        if any(h in nm for h in _CAP_SV_HINTS):
            out.append(sv)
    return out


def _fn_is_topup(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _TOPUP_FN_HINTS)


def _writes_collat_field(function) -> bool:
    """
    True if the function writes to ANY state variable. For structs held in
    mappings, Slither only surfaces the parent mapping in
    `state_variables_written`, so we can't reliably match a "collateral"
    field by name. Any storage write on a `topUp`-named function is a
    strong enough signal when combined with the cap-var gate on the
    contract level.
    """
    return bool(function.state_variables_written)


def _reads_any_of(function, svs) -> bool:
    read_set = set(function.state_variables_read)
    for sv in svs:
        if sv in read_set:
            return True
    return False


class TopUpBypassesCap(AbstractDetector):
    """
    Detect collateral/position top-up functions that do not re-check a
    protocol-defined maximum cap.
    """

    ARGUMENT = "topup-bypasses-cap"
    HELP = (
        "topUpCollateral / addMargin / increasePosition writes the "
        "collateral field without re-reading the max cap - traders bypass "
        "the per-position limit by topping up after opening"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Top-Up Bypasses Position Cap Recheck"
    WIKI_DESCRIPTION = (
        "A trading contract enforces `maxAllowedCollateral` inside "
        "`openTrade`, but a sibling `topUpCollateral` function increments "
        "the stored collateral without reading the cap state variable. "
        "A trader opens a trade at the cap, then tops up repeatedly to "
        "hold a position larger than the protocol intended - breaking "
        "risk limits and potentially harming the insurance fund. Observed "
        "in Ostium (Zellic slice_af)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function openTrade(uint256 amount) external {
    require(amount <= maxAllowedCollateral, "over cap");
    trades[id] = Trade(msg.sender, amount);
}

function topUpCollateral(uint256 id, uint256 extra) external {
    trades[id].collateral += extra;  // BUG: no cap recheck
}
```
1. Trader opens position at exactly `maxAllowedCollateral`.
2. Trader calls `topUpCollateral` repeatedly, adding `extra` each time.
3. Final position size >> maxAllowedCollateral; risk limits broken."""
    WIKI_RECOMMENDATION = (
        "After incrementing the collateral field, add `require(newTotal "
        "<= maxAllowedCollateral, \"OVER_CAP\")`. Extract a shared "
        "internal helper `_assertWithinCap(trade)` that both `openTrade` "
        "and `topUpCollateral` call."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            cap_svs = _find_cap_vars(contract)
            if not cap_svs:
                continue

            # Confirm the cap is actively used as a gate by at least one
            # *other* function in the contract (e.g. openTrade). Otherwise
            # we'd flag contracts where the cap is cosmetic storage.
            cap_used_elsewhere = False
            for f in contract.functions_and_modifiers_declared:
                if _fn_is_topup(f.name or ""):
                    continue
                if _reads_any_of(f, cap_svs):
                    cap_used_elsewhere = True
                    break
            if not cap_used_elsewhere:
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _fn_is_topup(function.name or ""):
                    continue
                if not _writes_collat_field(function):
                    continue
                if _reads_any_of(function, cap_svs):
                    continue
                info: DETECTOR_INFO = [
                    function,
                    " increments collateral/position storage but never "
                    "reads the cap state variable ",
                    cap_svs[0],
                    " - traders can open at the cap and then top up to "
                    "exceed it. Add a cap recheck after the increment.\n",
                ]
                results.append(self.generate_result(info))

        return results
