"""
paired_function_state_write_diff.py - Custom Slither detector.

Pattern (GTE-spot H-01/H-03, Kinetiq M-03, Virtuals H-06; slice_ac): Two
sibling functions that should produce inverse / paired state effects (single
vs batch, create vs amend, enqueue vs dequeue, delegate vs undelegate, stake
vs unstake) write DIFFERENT sets of state variables. One side touches a
tracking/index/ledger var, the other does not. Generic generalisation of the
deploy-undeploy accounting asymmetry, broadened to any inverse-pair shape and
any state variable (not just `*total*`/`*tracked*` names).

Detection strategy:
    1. For each non-vendored contract, find every pair `(forward, inverse)`
       of declared functions whose names match a known verb pair such as
       `(create, amend)`, `(enqueue, dequeue)`, `(open, close)`,
       `(delegate, undelegate)`.
    2. Compute the sets of state variables each side writes.
    3. Flag every state variable that the FORWARD writes and the INVERSE
       does not - but ONLY when the inverse is the "undo" side and the
       forward writes more than one variable (so we don't flag noise like a
       totally-unrelated constructor flag).
    4. Skip when forward.writes ⊆ inverse.writes.

Distinct from `deploy-undeploy-accounting-asymmetry`: that detector restricts
itself to a small set of "tracking" variable names (`total*`, `*staked*`,
`deployed*`, `*locked*`) and the `(deploy/undeploy)` verb family. This one
covers any state variable and a wider set of paired verbs (`delegate/
undelegate`, `enqueue/dequeue`, `open/close`, `create/amend`).

@author auditooor wave9
@pattern slice_ac GTE-spot / Kinetiq / Virtuals
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

# (forward verb, inverse verb). The inverse is the "undo" side that must write
# the same state. Keep these distinct from `deploy-undeploy-accounting-
# asymmetry` to avoid duplicate hits - that detector owns the
# `(deploy, undeploy)` / `(stake, unstake)` / `(deposit, withdraw)` family.
_PAIRS = [
    ("create", "amend"),
    ("create", "cancel"),
    ("open", "close"),
    ("enqueue", "dequeue"),
    ("delegate", "undelegate"),
    ("register", "deregister"),
    ("subscribe", "unsubscribe"),
    ("activate", "deactivate"),
]


def _starts_with(name: str, prefix: str) -> bool:
    n = (name or "").lower()
    return n == prefix or n.startswith(prefix)


def _stem(name: str, prefix: str) -> str:
    """
    Return the lowercase stem of `name` after removing the leading `prefix`.

    Example: _stem("addAdmin", "add") == "admin"
             _stem("delegate",  "delegate") == ""
             _stem("deployFunds", "deploy") == "funds"

    The stem is what the inverse function MUST share for the pair to be
    considered a matching forward/inverse pair. This prevents cross-stem
    FPs such as pairing `addAdmin` with `removeOperator` (SKILL_ISSUE #43).
    """
    n = (name or "").lower()
    if n == prefix:
        return ""
    if n.startswith(prefix):
        return n[len(prefix):]
    return n


class PairedFunctionStateWriteDiff(AbstractDetector):
    """Detect paired forward/inverse functions whose state-write sets differ."""

    ARGUMENT = "paired-function-state-write-diff"
    HELP = (
        "Inverse function fails to mirror state writes performed by the "
        "forward sibling - paired-function state divergence"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Paired Function State-Write Divergence"
    WIKI_DESCRIPTION = (
        "Many protocols expose paired forward / inverse operations such as "
        "`delegate`/`undelegate`, `enqueue`/`dequeue`, `create`/`amend`, "
        "`open`/`close`. Both sides must touch the same set of bookkeeping "
        "variables. When the inverse forgets to mirror one of the writes "
        "performed by the forward, every round-trip permanently desynchronises "
        "an index, total, ledger, or epoch counter - silently corrupting "
        "downstream solvency / fee / voting accounting."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public delegated;
mapping(address => uint256) public totalDelegated;

function delegate(address to, uint256 a) external {
    delegated[to] += a;
    totalDelegated[to] += a;
}

function undelegate(address to, uint256 a) external {
    delegated[to] -= a;
    // BUG: forgets totalDelegated[to] -= a
}
```
After a delegate/undelegate round-trip `totalDelegated[to]` is still inflated.
Voting weight, reward share, or fee accrual that reads `totalDelegated` is
permanently overstated."""
    WIKI_RECOMMENDATION = (
        "Route every state mutation through a single internal helper that "
        "takes a sign argument, or unit-test that the post-state of "
        "`forward(x); inverse(x)` matches the pre-state for every paired "
        "function family."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            declared = [
                f for f in contract.functions_declared
                if not f.is_constructor
            ]

            for fwd_prefix, inv_prefix in _PAIRS:
                fwds = [f for f in declared if _starts_with(f.name, fwd_prefix)]
                invs = [f for f in declared if _starts_with(f.name, inv_prefix)]
                if not fwds or not invs:
                    continue

                for fwd in fwds:
                    fwd_writes = {sv for sv in fwd.state_variables_written}
                    if len(fwd_writes) < 2:
                        # Need at least two writes to detect divergence
                        continue
                    fwd_stem = _stem(fwd.name, fwd_prefix)
                    for inv in invs:
                        # SKILL_ISSUE #43: Only pair functions that share the
                        # same stem after the verb prefix. This prevents
                        # `addAdmin` ↔ `removeOperator` cross-stem FPs.
                        if _stem(inv.name, inv_prefix) != fwd_stem:
                            continue
                        inv_writes = {sv for sv in inv.state_variables_written}
                        missing = fwd_writes - inv_writes
                        if not missing:
                            continue
                        # If forward writes vars the inverse never touches
                        # AND the inverse writes at least one shared var with
                        # forward (otherwise they're unrelated), flag.
                        shared = fwd_writes & inv_writes
                        if not shared:
                            continue

                        offending = sorted(
                            missing, key=lambda v: v.name or ""
                        )[0]
                        info: DETECTOR_INFO = [
                            inv,
                            " in ",
                            contract,
                            " is the inverse of ",
                            fwd,
                            " but does not write state variable ",
                            offending,
                            " - paired-function state divergence.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
