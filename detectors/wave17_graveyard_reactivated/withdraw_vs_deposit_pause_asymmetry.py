"""
withdraw_vs_deposit_pause_asymmetry.py - Custom Slither detector.

Pattern (BakerFi M-06/M-12, slice_ab): A pausable vault gates `deposit` (or
`mint`) with a `whenNotPaused` modifier but forgets to gate `withdraw` (or
`redeem`), or vice versa. During an emergency pause one direction is blocked
while the other isn't, letting users extract value asymmetrically (deposit
when price is favourable; withdraw while the protocol is frozen).

Detection strategy:
    1. For each non-vendored contract, find functions whose names start with
       `deposit`/`mint`/`stake` (entry side) and `withdraw`/`redeem`/`unstake`
       (exit side).
    2. For each side, check whether the function's modifier list contains a
       modifier named matching `(?i)whenNotPaused|notPaused|nonPaused`.
    3. If at least one entry function and one exit function exist on the
       contract, AND the modifier coverage is asymmetric across the two
       sides, flag the side that is missing the modifier.

@author auditooor wave9
@pattern slice_ab BakerFi M-06 / M-12
"""

import re
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

_ENTRY_PREFIXES = ("deposit", "mint", "stake", "supply")
_EXIT_PREFIXES = ("withdraw", "redeem", "unstake", "exit")

_PAUSE_MOD_RE = re.compile(
    r"^(when[_]?not[_]?paused|not[_]?paused|nonpaused|whenpaused)$",
    re.IGNORECASE,
)


def _starts_with_any(name: str, prefixes) -> bool:
    n = (name or "").lower()
    return any(n == p or n.startswith(p) for p in prefixes)


def _has_pause_modifier(function) -> bool:
    for mod in getattr(function, "modifiers", []) or []:
        nm = getattr(mod, "name", "") or ""
        if _PAUSE_MOD_RE.match(nm):
            return True
    return False


class WithdrawVsDepositPauseAsymmetry(AbstractDetector):
    """Detect deposit/withdraw pairs with asymmetric pause-modifier coverage."""

    ARGUMENT = "withdraw-vs-deposit-pause-asymmetry"
    HELP = (
        "deposit and withdraw functions have asymmetric whenNotPaused "
        "coverage - pause exposes a one-sided arbitrage / drain"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Pausable Vault - Asymmetric Pause Coverage"
    WIKI_DESCRIPTION = (
        "A pausable vault that gates only one side of the deposit / withdraw "
        "pair leaves the other side open during an emergency pause. If "
        "deposits are paused but withdrawals are not, users drain reserves "
        "while the team thinks the contract is frozen. If withdrawals are "
        "paused but deposits are not, users top up at a stale share price "
        "and dilute existing holders. Both directions of the asymmetry are "
        "exploitable."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function deposit(uint256 a) external whenNotPaused { /* ... */ }
function withdraw(uint256 a) external { /* ... */ }   // BUG: no modifier
```
1. Admin discovers a price-oracle bug and calls `pause()`.
2. Withdraw is unguarded; an attacker drains the vault before the team can
   migrate funds."""
    WIKI_RECOMMENDATION = (
        "Apply the same `whenNotPaused` (or `whenPaused`) modifier to every "
        "function in a deposit / withdraw / mint / redeem family, or route "
        "all entries and exits through internal helpers gated by the pause "
        "check."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Contract must declare a pause modifier somewhere - otherwise
            # there's no pausing intent to be asymmetric about.
            has_pause_anywhere = False
            for mod in contract.modifiers_declared:
                if _PAUSE_MOD_RE.match(mod.name or ""):
                    has_pause_anywhere = True
                    break
            if not has_pause_anywhere:
                continue

            entries = []
            exits = []
            for fn in contract.functions_declared:
                if fn.is_constructor or fn.visibility not in ("public", "external"):
                    continue
                if _starts_with_any(fn.name, _ENTRY_PREFIXES):
                    entries.append(fn)
                elif _starts_with_any(fn.name, _EXIT_PREFIXES):
                    exits.append(fn)

            if not entries or not exits:
                continue

            entries_paused = [f for f in entries if _has_pause_modifier(f)]
            exits_paused = [f for f in exits if _has_pause_modifier(f)]

            # Symmetric → fine
            if (entries_paused and exits_paused and
                    len(entries_paused) == len(entries) and
                    len(exits_paused) == len(exits)):
                continue
            # Neither side gated → not this bug (no pause intent on this pair)
            if not entries_paused and not exits_paused:
                continue

            missing_side, paired_side = None, None
            if entries_paused and not exits_paused:
                missing_side = exits
                paired_side = entries_paused[0]
                side_label = "withdraw"
            elif exits_paused and not entries_paused:
                missing_side = entries
                paired_side = exits_paused[0]
                side_label = "deposit"
            else:
                # Mixed coverage on one side - flag the unguarded ones.
                if len(entries_paused) < len(entries):
                    missing_side = [f for f in entries if not _has_pause_modifier(f)]
                    paired_side = exits_paused[0] if exits_paused else entries_paused[0]
                    side_label = "deposit"
                elif len(exits_paused) < len(exits):
                    missing_side = [f for f in exits if not _has_pause_modifier(f)]
                    paired_side = entries_paused[0] if entries_paused else exits_paused[0]
                    side_label = "withdraw"
                else:
                    continue

            if not missing_side:
                continue

            for fn in missing_side:
                info: DETECTOR_INFO = [
                    fn,
                    " in ",
                    contract,
                    " is missing the whenNotPaused modifier applied to its "
                    "paired ",
                    paired_side,
                    " - asymmetric pause coverage on a ",
                    side_label,
                    " path lets users transact while the other side is frozen.\n",
                ]
                results.append(self.generate_result(info))

        return results
