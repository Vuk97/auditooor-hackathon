"""
remove_milestone_no_confirmed_guard.py - Custom Slither detector.

Pattern (Zellic slice_af Metavest, HIGH): an `allocation`/`vest`/`milestone`
contract exposes a `removeMilestone` / `removeCheckpoint` / `deleteStage`
admin function that pops an element from the milestones array, but does NOT
check whether the target element has already been `confirmed` (or
`completed`/`executed`/`finalized`). Removing a confirmed milestone leaves
`milestoneUnlockedTotal` inflated but the corresponding Milestone record is
gone - accounting is corrupted and the grantee may either lose vested tokens
or be able to re-claim them.

Detection strategy:
    1. For each declared function whose lowercased name contains a "remove"
       verb ({"remove", "delete", "cancel", "revoke"}) AND a milestone noun
       ({"milestone", "stage", "checkpoint", "tranche", "phase"}).
    2. Confirm the function writes state (is a mutator).
    3. Walk every node's IR list for a `Member` IR whose `variable_right`
       name is one of the "confirmed" flag hints
       ({"confirmed", "completed", "complete", "finalized", "finished",
       "executed", "done", "settled", "unlocked"}).
    4. If no such Member read exists → the function never reads a completion
       flag → no guard → flag.

Dedup: no wave1..10 detector covers milestone-specific remove-without-
confirmed-guard. Related but distinct: `liquidation_partial_clear` (wave5)
targets struct zeroing on liquidation; `order_status_non_monotonic` (wave3)
targets state-machine forward violation.

@author auditooor wave11
@pattern slice_af Metavest
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
from slither.slithir.operations import Member
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_REMOVE_VERBS = ("remove", "delete", "cancel", "revoke")
_MILESTONE_NOUNS = (
    "milestone",
    "stage",
    "checkpoint",
    "tranche",
    "phase",
    "vestingstep",
    "vest",
)

_CONFIRMED_FLAG_NAMES = frozenset({
    "confirmed",
    "completed",
    "complete",
    "finalized",
    "finished",
    "executed",
    "done",
    "settled",
    "unlocked",
    "claimed",
    "vested",
})


def _fn_is_remove_milestone(name: str) -> bool:
    n = name.lower()
    if not any(v in n for v in _REMOVE_VERBS):
        return False
    return any(noun in n for noun in _MILESTONE_NOUNS)


def _reads_confirmed_flag(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Member):
                continue
            vr = getattr(ir, "variable_right", None)
            if vr is None:
                continue
            name = (getattr(vr, "name", "") or "").lower()
            if name in _CONFIRMED_FLAG_NAMES:
                return True
    return False


class RemoveMilestoneNoConfirmedGuard(AbstractDetector):
    """
    Detect removeMilestone/deleteStage functions that never check a
    `confirmed` / `completed` / `executed` flag on the target element.
    """

    ARGUMENT = "remove-milestone-no-confirmed-guard"
    HELP = (
        "removeMilestone / deleteStage pops a milestone without checking "
        "whether it has been confirmed/executed - removing a confirmed "
        "milestone corrupts unlock accounting"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Remove Milestone Without Confirmed Guard"
    WIKI_DESCRIPTION = (
        "A vesting / allocation contract lets an admin remove milestones "
        "from a user's schedule, but the removal path does not check "
        "whether the milestone has already been `confirmed`. Confirmation "
        "increments an `unlockedTotal` counter; removing a confirmed "
        "milestone leaves the counter inflated but the record is gone - "
        "the grantee's accounting is corrupted and either their vested "
        "balance becomes inaccessible or they can double-claim. Observed "
        "in Metavest `removeMetavestMilestone` (Zellic slice_af)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Milestone { uint256 amount; bool confirmed; }
mapping(uint256 => Milestone[]) milestones;
mapping(uint256 => uint256) milestoneUnlockedTotal;

function confirmMilestone(uint256 id, uint256 i) external {
    milestones[id][i].confirmed = true;
    milestoneUnlockedTotal[id] += milestones[id][i].amount;
}

function removeMilestone(uint256 id, uint256 i) external onlyAuthority {
    // BUG: no `require(!milestones[id][i].confirmed)`
    milestones[id][i] = milestones[id][milestones[id].length - 1];
    milestones[id].pop();
}
```
1. Milestone M (amount = 1000) is confirmed → unlockedTotal += 1000.
2. Authority calls `removeMilestone` on M anyway.
3. Now `milestones[id]` no longer contains M, but `unlockedTotal = 1000`.
4. Downstream `withdraw` uses `unlockedTotal - alreadyPaid`; if the user
   hadn't yet claimed, they can drain 1000 tokens that are no longer
   backed by any milestone."""
    WIKI_RECOMMENDATION = (
        "Add `require(!milestones[id][i].confirmed, \"ALREADY_CONFIRMED\")` "
        "at the top of the removal function. Alternatively, flip the "
        "semantics: track `archived` instead of pop-and-swap so downstream "
        "totals remain consistent."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _fn_is_remove_milestone(function.name or ""):
                    continue
                # Note: we do NOT gate on `state_variables_written` here -
                # array `pop()` / element shuffle on a struct mapping does
                # not show up in Slither's `state_variables_written` list.
                # The function-name match on "remove+milestone" is a tight
                # enough pre-filter.
                if _reads_confirmed_flag(function):
                    continue
                info: DETECTOR_INFO = [
                    function,
                    " removes a milestone/stage but never reads any "
                    "`confirmed`/`completed`/`executed` flag on the "
                    "target element - removing a confirmed milestone "
                    "corrupts the unlocked-total accounting. Add a guard "
                    "`require(!milestone.confirmed)`.\n",
                ]
                results.append(self.generate_result(info))

        return results
