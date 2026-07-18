"""
deploy_undeploy_accounting_asymmetry.py - Custom Slither detector.

Pattern (BakerFi H-03, LoopFi H-01, slice_ab): A vault has two functions whose
names form a symmetric pair (`deploy` / `undeploy`, `stake` / `unstake`,
`lock` / `unlock`, `deposit` / `withdraw`) that are supposed to be inverse
operations on a tracked accounting variable (`deployedAmount`, `lastBalance`,
`totalStaked`, …). One side writes to the variable, the other does NOT - so
after a round-trip the accounting is permanently off.

Detection strategy:
    1. For each non-vendored contract, build a name-indexed map of declared
       functions and walk a list of symmetric verb pairs.
    2. For every pair `(deploySide, undeploySide)` that BOTH exist on the
       contract, compute the set of state variables each side writes.
    3. Flag every state variable that the deploySide writes whose name
       contains a "tracking" keyword (`deployed`, `staked`, `balance`,
       `total`, `tracked`) but that the undeploySide does NOT write.

@author auditooor wave9
@pattern slice_ab BakerFi H-03 / LoopFi H-01
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


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup")

# (deploy-side prefix, undeploy-side prefix). Comparison uses lowercase
# "starts-with" to capture variants like `deployFunds`/`undeployFunds`.
_PAIRS = [
    ("deploy", "undeploy"),
    ("stake", "unstake"),
    ("lock", "unlock"),
    ("deposit", "withdraw"),
    ("supply", "withdraw"),
    ("mint", "burn"),
    ("wrap", "unwrap"),
]

_TRACK_KEYWORDS = ("deployed", "staked", "balance", "total", "tracked", "locked", "supplied")


def _is_tracking_var(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in _TRACK_KEYWORDS)


def _matches_side(fn_name: str, prefix: str) -> bool:
    n = (fn_name or "").lower()
    return n == prefix or n.startswith(prefix)


def _stem(fn_name: str, prefix: str) -> str:
    """
    Return the lowercase stem of `fn_name` after stripping the verb prefix.
    Used to enforce same-stem pairing (SKILL_ISSUE #43). `deployFunds` with
    prefix `deploy` yields stem `funds`; the inverse must be `undeployFunds`
    (stem `funds`) - NOT `unwrapSomething`.
    """
    n = (fn_name or "").lower()
    if n == prefix:
        return ""
    if n.startswith(prefix):
        return n[len(prefix):]
    return n


class DeployUndeployAccountingAsymmetry(AbstractDetector):
    """Detect symmetric deploy/undeploy pairs where the inverse fails to
    update a tracking accounting variable."""

    ARGUMENT = "deploy-undeploy-accounting-asymmetry"
    HELP = (
        "Inverse of a deploy/stake/lock function fails to update the "
        "tracking accounting variable - round-trip leaves it stale"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Deploy/Undeploy Accounting Asymmetry"
    WIKI_DESCRIPTION = (
        "Vaults that delegate funds to an external strategy typically expose "
        "two inverse functions (`deploy`/`undeploy`, `stake`/`unstake`, "
        "`lock`/`unlock`) that each maintain a local tracking variable like "
        "`deployedAmount` or `totalStaked`. When only the forward operation "
        "writes to that tracking variable but the inverse does not, every "
        "round-trip leaves the variable permanently overstated. Downstream "
        "TVL, share price, fee accrual, or solvency checks then run on a "
        "permanently-corrupted accounting view."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public deployedAmount;

function deploy(uint256 a) external {
    deployedAmount += a;
    pool.deposit(a);
}

function undeploy(uint256 a) external {
    pool.withdraw(a);
    // BUG: missing deployedAmount -= a;
}
```
1. Strategist calls `deploy(100)` → deployedAmount = 100.
2. Strategist calls `undeploy(100)` → deployedAmount STILL == 100 even though
   the strategy holds nothing.
3. `totalAssets()` (which adds `idle + deployedAmount`) over-reports by 100,
   inflating share price and letting the next withdrawer drain real funds."""
    WIKI_RECOMMENDATION = (
        "For every state variable touched by the forward operation, mirror "
        "the corresponding write in the inverse. Prefer extracting both "
        "operations into an internal helper so the accounting set stays "
        "in lockstep by construction."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            declared = list(contract.functions_declared)

            for fwd_prefix, inv_prefix in _PAIRS:
                fwd_funcs = [
                    f for f in declared
                    if not f.is_constructor and _matches_side(f.name, fwd_prefix)
                ]
                inv_funcs = [
                    f for f in declared
                    if not f.is_constructor and _matches_side(f.name, inv_prefix)
                ]
                if not fwd_funcs or not inv_funcs:
                    continue

                for fwd in fwd_funcs:
                    fwd_writes = {sv for sv in fwd.state_variables_written}
                    if not fwd_writes:
                        continue

                    # Tracking variables touched by the forward operation.
                    fwd_tracking = {sv for sv in fwd_writes if _is_tracking_var(sv.name)}
                    if not fwd_tracking:
                        continue

                    fwd_stem = _stem(fwd.name, fwd_prefix)
                    for inv in inv_funcs:
                        # SKILL_ISSUE #43: require same stem - `stakeA` pairs
                        # with `unstakeA`, not `unstakeB`.
                        if _stem(inv.name, inv_prefix) != fwd_stem:
                            continue
                        inv_writes = {sv for sv in inv.state_variables_written}
                        missing = fwd_tracking - inv_writes
                        if not missing:
                            continue

                        # Pick the first missing tracking var for the report.
                        offending = sorted(missing, key=lambda v: v.name or "")[0]
                        info: DETECTOR_INFO = [
                            inv,
                            " in ",
                            contract,
                            " is the inverse of ",
                            fwd,
                            " but does not update tracking state variable ",
                            offending,
                            " - round-trip leaves accounting permanently stale.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
