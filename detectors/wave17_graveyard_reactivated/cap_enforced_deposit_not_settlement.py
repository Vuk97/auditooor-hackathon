"""
cap_enforced_deposit_not_settlement.py - Custom Slither detector.

Pattern (Megapot H-03, slice_ad): An LP pool / vault cap is enforced inside
the user-facing `deposit` path with `require(pool + amount <= cap)`, but
the settlement / accrual / payout path ALSO writes to the same pool state
variable and forgets the cap check. Rewards or winnings pushed through the
second path silently blow past the configured cap.

Detection strategy:
    1. For each contract, collect state variables whose name matches
       `(cap|limit|max|ceiling)`.
    2. Identify a "protected" state variable P: one that is written by a
       function whose body contains a require/assert that reads BOTH P and
       a cap var via a Binary LESS/LESS_EQUAL compare, and whose name
       starts with `deposit|stake|mint|supply|addliquidity|fund`.
    3. Identify any OTHER function in the same contract that writes the
       same P without any require/assert reading the cap var. The function
       name should match a settlement/accrual/claim/payout pattern.
    4. Flag that function.

@author auditooor wave11
@pattern slice_ad Megapot H-03
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
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_CAP_RE = re.compile(r"(cap|limit|max|ceiling)", re.IGNORECASE)
_DEPOSIT_RE = re.compile(
    r"^(deposit|stake|mint|supply|addliquidity|fund|contribute)",
    re.IGNORECASE,
)
_SETTLE_RE = re.compile(
    r"(settle|accrue|payout|reward|distribute|claim|fulfill|finalize|resolve|notify)",
    re.IGNORECASE,
)
_LE = frozenset({BinaryType.LESS_EQUAL, BinaryType.LESS})


def _cap_check_reads(function, cap_names):
    """Return the set of state var names read inside any require/assert
    node whose IR contains a LESS/LESS_EQUAL Binary referencing a cap var."""
    reads = set()
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        has_le = any(
            isinstance(ir, Binary) and ir.type in _LE
            for ir in node.irs
        )
        if not has_le:
            continue
        node_reads = {sv.name for sv in node.state_variables_read}
        if node_reads & cap_names:
            reads |= node_reads
    return reads


class CapEnforcedDepositNotSettlement(AbstractDetector):
    """Flag pool state writes in settlement paths that skip the deposit cap check."""

    ARGUMENT = "cap-enforced-deposit-not-settlement"
    HELP = (
        "Pool cap enforced on deposit path but a settlement/accrual function "
        "also writes the pool state without the cap check - cap bypassed"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Cap Enforced On Deposit, Bypassed On Settlement"
    WIKI_DESCRIPTION = (
        "The LP / pool cap is enforced inside the `deposit` path via "
        "`require(pool + amount <= cap)`, but a settlement or reward-accrual "
        "path also increments the same `pool` state variable without the "
        "cap check. Winnings, yield, or rebates pushed through that path "
        "silently push the pool above the configured maximum. "
        "Source: Megapot H-03 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public lpPool;
uint256 public lpPoolCap;

function deposit(uint256 amount) external {
    require(lpPool + amount <= lpPoolCap, "cap");
    lpPool += amount;
}

function settleDraw(uint256 winnings) external {
    lpPool += winnings;                  // BUG: no cap check
}
```
1. Deposits fill the LP pool to exactly `lpPoolCap`.
2. A draw is settled with positive winnings; `settleDraw` adds them to
   `lpPool`, pushing it past the cap.
3. Governance assumption (LP exposure ceiling) is violated; downstream
   solvency math breaks."""
    WIKI_RECOMMENDATION = (
        "Replicate the cap check in every function that increments the "
        "pool variable - including settlement, accrual, payout and reward "
        "distribution paths. Better: centralise the cap check in an "
        "internal `_increaseLpPool` helper."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            cap_svs = [
                sv for sv in contract.state_variables
                if _CAP_RE.search(sv.name or "")
            ]
            if not cap_svs:
                continue
            cap_names = {sv.name for sv in cap_svs}

            # Find protected pool state variables via deposit-path functions
            # that check the cap.
            protected = {}   # pool_var_name -> deposit_function
            for f in contract.functions_and_modifiers_declared:
                if f.is_constructor:
                    continue
                if not _DEPOSIT_RE.search(f.name or ""):
                    continue
                cap_reads = _cap_check_reads(f, cap_names)
                if not cap_reads:
                    continue
                # Pool state vars = written state vars minus cap vars.
                written = {sv.name for sv in f.state_variables_written}
                pool_targets = written - cap_names
                for p in pool_targets:
                    protected.setdefault(p, f)

            if not protected:
                continue

            # Look for other functions that write a protected var without
            # a cap check.
            for f in contract.functions_and_modifiers_declared:
                if f.is_constructor or f.view or f.pure:
                    continue
                if _DEPOSIT_RE.search(f.name or ""):
                    continue
                if not _SETTLE_RE.search(f.name or ""):
                    continue
                written = {sv.name for sv in f.state_variables_written}
                touched = written & set(protected.keys())
                if not touched:
                    continue
                if _cap_check_reads(f, cap_names):
                    continue

                one = sorted(touched)[0]
                info: DETECTOR_INFO = [
                    f,
                    " writes pool state '",
                    one,
                    "' without re-applying the cap check enforced by ",
                    protected[one],
                    ". Cap bypassable on settlement/accrual path.\n",
                ]
                results.append(self.generate_result(info))

        return results
