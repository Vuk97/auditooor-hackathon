"""
session_cap_stateless.py - Custom Slither detector.

Pattern (AA Session Key - Biconomy):
    An Account Abstraction session-key validator enforces `maxAmount` / `cap` /
    `limit` per-transaction via a LESS_EQUAL Binary comparison against a struct
    member field, but never accumulates usage into a mapping (no state variable
    whose name contains "used", "consumed", "total", or "spent" is written by
    the executing function).

    Without cumulative tracking the attacker issues N small transactions, each
    below the per-tx cap, and drains an amount up to N * maxAmount - far
    exceeding the intended session budget.

Detection strategy:
    1. Walk all functions with any LESS_EQUAL Binary IR where the right-hand
       operand is a ReferenceVariable derived from a struct Member access
       whose field name contains "maxamount", "cap", or "limit" (case-insensitive).
    2. Check whether the function WRITES to any state variable whose name
       (lowercased) contains "used", "consumed", "total", or "spent".
    3. If cap-check present AND no cumulative write → flag.

Dedup check:
    slither --list-detectors | grep -i session  → nothing
    slither --list-detectors | grep -i cap      → nothing matching this pattern
    NOVEL.

Impact: HIGH - unlimited session spending possible.
Confidence: LOW - AA-specific; many non-AA cap patterns share this shape.

Source: reference/corpus_mined/slice_ad.md - Biconomy AA session key.
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
from slither.slithir.operations import Binary, BinaryType, Member
from slither.slithir.variables import ReferenceVariable
from slither.utils.output import Output


# Field name substrings that look like a per-tx cap field
_CAP_FIELD_KEYWORDS = ("maxamount", "cap", "limit", "maxvalue", "quota")

# State variable name substrings that represent cumulative usage tracking
_CUMULATIVE_KEYWORDS = ("used", "consumed", "total", "spent", "cumul", "accum")

_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _function_has_body(function) -> bool:
    return any(node.irs for node in function.nodes)


def _find_cap_check_node(function):
    """
    Return the first node that has a LESS_EQUAL Binary where the right-hand
    operand is a ReferenceVariable that originates from a struct Member access
    whose field name contains a cap keyword.  Returns None if not found.

    Strategy: build a map {id(ref_lvalue): field_name} from Member IRs in the
    same function, then scan Binary(LESS_EQUAL) whose variable_right id is in
    that map with a cap field name.
    """
    # Pass 1: collect Member lvalue → field name
    ref_to_field = {}
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Member):
                field_name = str(ir.variable_right).lower()
                ref_to_field[id(ir.lvalue)] = field_name

    # Pass 2: find LESS_EQUAL where right-hand is a cap-named struct field
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type != BinaryType.LESS_EQUAL:
                continue
            vr = ir.variable_right
            if not isinstance(vr, ReferenceVariable):
                continue
            field_name = ref_to_field.get(id(vr), "")
            if any(kw in field_name for kw in _CAP_FIELD_KEYWORDS):
                return node
    return None


def _writes_cumulative_state(function) -> bool:
    """
    Return True if any state variable written by this function has a name
    that suggests cumulative usage tracking (used/consumed/total/spent/...).
    Uses function.state_variables_written - pre-computed by Slither.
    """
    for sv in function.state_variables_written:
        name_lower = sv.name.lower()
        if any(kw in name_lower for kw in _CUMULATIVE_KEYWORDS):
            return True
    return False


class SessionCapStateless(AbstractDetector):
    """
    AA session-key validator enforces per-tx cap but has no cumulative tracking.
    """

    ARGUMENT = "session-cap-stateless"
    HELP = (
        "AA session key validator enforces per-tx maxAmount cap with no "
        "cumulative usage tracking - budget can be drained by many small txs"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "AA Session Key Stateless Cap - Missing Cumulative Usage Tracking"
    WIKI_DESCRIPTION = (
        "Account Abstraction session key validators commonly enforce a "
        "`maxAmount`/`cap`/`limit` per transaction via a simple comparison "
        "(e.g. `require(amount <= sd.maxAmount)`). Without a corresponding "
        "cumulative-usage mapping (e.g. `usedAmount[sessionId] += amount`), "
        "an attacker holding a valid session key can issue arbitrarily many "
        "transactions, each just below the per-tx cap, until the full session "
        "budget (or entire protocol reserve) is drained. The intended session "
        "budget is thus completely unenforced. Observed in Biconomy's AA "
        "session-key module audit (HIGH severity)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct SessionData { address key; uint256 maxAmount; uint256 validUntil; }
mapping(bytes32 => SessionData) sessions;
// No usage accumulator mapping.

function executeWithSession(bytes32 sid, uint256 amount, ...) external {
    SessionData memory sd = sessions[sid];
    require(amount <= sd.maxAmount);   // per-tx only - BUG
    // ... execute action with amount
}
```
Session registered with maxAmount = 100 USDC.
Attacker calls executeWithSession 1000 times with amount = 99 USDC each call.
Total drained: 99,000 USDC. No cumulative check stops them."""
    WIKI_RECOMMENDATION = (
        "Add a cumulative usage mapping: `mapping(bytes32 => uint256) public usedAmount`. "
        "Before each execution: `uint256 newUsed = usedAmount[sessionId] + amount; "
        "require(newUsed <= sd.maxAmount, 'exceeds cumulative cap'); "
        "usedAmount[sessionId] = newUsed;`. "
        "Consider also enforcing a per-period reset if that is the intended design."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Must have a body
                if not _function_has_body(function):
                    continue

                # Step 1: find a per-tx cap check (LESS_EQUAL against cap field)
                cap_node = _find_cap_check_node(function)
                if cap_node is None:
                    continue

                # Step 2: if function writes a cumulative tracker → safe
                if _writes_cumulative_state(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " enforces a per-transaction cap (LESS_EQUAL against a "
                    "maxAmount/cap/limit struct field) but writes no cumulative "
                    "usage tracking state variable. An AA session key can be "
                    "reused to drain the protocol in many small transactions "
                    "each below the cap.\n",
                ]
                results.append(self.generate_result(info))

        return results
