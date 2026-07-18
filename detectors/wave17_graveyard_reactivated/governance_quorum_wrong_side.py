"""
governance_quorum_wrong_side.py - Custom Slither detector.

Pattern (IQ AI H-01, slice_ab governance-quorum-wrong-side): Governance
quorum check compares `againstVotes` / `abstainVotes` against the quorum
threshold instead of `forVotes`. The proposal can therefore be marked
passed even though no one supported it.

Detection strategy:
    1. Walk all functions declared on each non-vendored contract.
    2. For every Binary IR with a comparison type
       (>=, >, <, <=, ==), check whether either operand is a state
       variable whose name (case-insensitive) contains "againstvote",
       "novote", or "abstainvote", AND the other operand is a state
       variable whose name contains "quorum".
    3. Flag any such function - comparing the wrong side of the tally
       against the quorum is a structural bug.

@author auditooor wave9
@pattern slice_ab IQ AI H-01
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

_WRONG_SIDE_SUBSTRINGS = ("againstvote", "novote", "abstainvote")
_QUORUM_SUBSTRINGS = ("quorum",)

_COMPARISON_TYPES = frozenset({
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.EQUAL,
    BinaryType.NOT_EQUAL,
})


def _name_matches(var, substrings) -> bool:
    nm = (getattr(var, "name", "") or "").lower()
    return any(s in nm for s in substrings)


class GovernanceQuorumWrongSide(AbstractDetector):
    """Flag governance functions that compare against/abstain votes against quorum."""

    ARGUMENT = "governance-quorum-wrong-side"
    HELP = (
        "Quorum check compares againstVotes/abstainVotes to quorum instead of "
        "forVotes - proposal can pass with zero support"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Governance Quorum Compared Against Wrong Side"
    WIKI_DESCRIPTION = (
        "A governance contract that determines whether a proposal has reached "
        "quorum by comparing `againstVotes` or `abstainVotes` to the quorum "
        "threshold (instead of `forVotes`) inverts the intended semantics. A "
        "proposal can be marked as passed when nobody actually voted for it, "
        "or - symmetrically - never reach quorum no matter how much support it "
        "receives. The same wrong-side mistake was confirmed in the IQ AI H-01 "
        "Code4rena finding."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function isPassed() external view returns (bool) {
    return againstVotes >= quorum; // BUG: should be forVotes
}
```
1. Attacker submits a malicious proposal.
2. Honest holders vote AGAINST it; `againstVotes` grows past `quorum`.
3. `isPassed()` returns true; the malicious proposal is executed."""
    WIKI_RECOMMENDATION = (
        "Compare `forVotes` (not `againstVotes` / `abstainVotes`) against the "
        "quorum threshold, and additionally require `forVotes > againstVotes`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                flagged_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type not in _COMPARISON_TYPES:
                            continue
                        left = ir.variable_left
                        right = ir.variable_right
                        # Need wrong-side var on one side and quorum-named var
                        # on the other side.
                        wrong_left = _name_matches(left, _WRONG_SIDE_SUBSTRINGS)
                        wrong_right = _name_matches(right, _WRONG_SIDE_SUBSTRINGS)
                        quorum_left = _name_matches(left, _QUORUM_SUBSTRINGS)
                        quorum_right = _name_matches(right, _QUORUM_SUBSTRINGS)
                        if (wrong_left and quorum_right) or (wrong_right and quorum_left):
                            flagged_node = node
                            break
                    if flagged_node is not None:
                        break
                if flagged_node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " compares the wrong side of the tally (againstVotes / "
                    "abstainVotes) against quorum at ",
                    flagged_node,
                    " - proposals can pass with zero support. Compare "
                    "forVotes >= quorum instead.\n",
                ]
                results.append(self.generate_result(info))

        return results
