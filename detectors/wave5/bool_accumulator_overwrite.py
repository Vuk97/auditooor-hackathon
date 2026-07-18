"""
bool_accumulator_overwrite.py — Custom Slither detector.

ARG: bool-accumulator-overwrite
SEVERITY: LOW

Pattern: A bool variable is assigned `true` at some node in a function, then
later in the same function it is re-assigned via a plain `=` whose RHS is NOT
`true` and does NOT include the variable itself on the RHS (i.e. not `var ||
expr` or `var |= expr`).  When the second condition evaluates to false the
earlier `true` is silently discarded.

Concrete real-world instance (BasisOS, via slice_aa.md LOGLAB-13):
    shouldPause = exceedsThreshold;   // BUG — should be shouldPause |= exceedsThreshold

IR reality (verified against fixture):

  Vulnerable:
    NODE 2 EXPRESSION:  shouldPause = true
      Assignment: shouldPause(bool) := True(bool)          ← lvalue=StateVariable, rvalue=Constant(True)
    NODE 4 EXPRESSION:  shouldPause = (b > 100)
      Binary:   TMP_1(bool) = b > 100
      Assignment: shouldPause(bool) := TMP_1(bool)         ← lvalue=StateVariable, rvalue=TemporaryVariable
                                                             TMP_1 produced by plain Binary (not OROR)

  Clean (shouldPause = shouldPause || (b > 100)):
    NODE 4 EXPRESSION:  shouldPause = shouldPause || (b > 100)
      Binary:   TMP_1(bool) = b > 100
      Binary:   TMP_2(bool) = shouldPause || TMP_1         ← OROR with shouldPause on left
      Assignment: shouldPause(bool) := TMP_2(bool)         ← rvalue produced by OROR

Detection logic:
1. Walk all functions+modifiers declared in each contract.
2. For each function, do a single linear pass over nodes in CFG order.
   Build two tracking structures:
     - seen_true_assign: set of variable identities that were assigned `true`
       at some earlier node.
     - tmp_producer_map: id(TemporaryVariable) → producing IR (so we can
       inspect what feeds the rvalue of a later Assignment).
3. For each Assignment IR where:
     a. lvalue is a bool-typed StateVariable or LocalVariable
     b. rvalue is Constant(True) → add to seen_true_assign (early-set path)
     c. rvalue is NOT Constant(True), the variable is already in seen_true_assign,
        AND the rvalue is not itself produced by a Binary(OROR) that reads the
        same variable → flag as accumulator overwrite.
4. Emit one result per (function, variable) pair to avoid duplicate noise.

Gotchas observed during development:
- `Assignment` IS importable from slither.slithir.operations (unlike some
  gotchas listed for older waves; confirmed working in current Slither).
- rvalue for the second assignment is a TemporaryVariable, not a Constant.
  We must chase the producer chain one level to see if it came from OROR.
- Clean pattern `shouldPause = shouldPause || expr` produces a Binary(OROR)
  where ir.read includes the bool variable itself.  Check `bool_var in
  producer.read` as the safe-pattern guard.
- Applies to both StateVariable and LocalVariable (local bool accumulators
  used as multi-condition pause/halt flags are equally common).

Source: reference/corpus_mined/slice_aa.md — BasisOS finding LOGLAB-13.
Dedup: `slither --list-detectors | grep -i bool` → only `boolean-cst`
       (misuse of Boolean constant) and `boolean-equal` (comparison to
       Boolean constant) exist.  Neither catches the accumulator-overwrite
       pattern.  Novel.

@author auditooor
@pattern wave5 bool-accumulator-overwrite
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
from slither.slithir.operations import Assignment, Binary
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables import Constant, TemporaryVariable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.utils.output import Output

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _is_bool_var(var) -> bool:
    """Return True if the variable has a bool (or bool-like) type."""
    t = getattr(var, "type", None)
    if t is None:
        return False
    return str(t) == "bool"


def _is_true_constant(val) -> bool:
    """Return True if val is a Constant whose value is the boolean True."""
    if not isinstance(val, Constant):
        return False
    return val.value is True


def _rvalue_is_or_of_var(rvalue, bool_var, tmp_producer_map: dict) -> bool:
    """
    Return True if rvalue is produced by a Binary(OROR) that reads bool_var.

    This covers:
      shouldPause = shouldPause || expr    → TMP produced by OROR has shouldPause in .read
      shouldPause |= expr                  → same IR pattern (Slither desugars |= to ||)
    """
    if not isinstance(rvalue, TemporaryVariable):
        return False
    producer = tmp_producer_map.get(id(rvalue))
    if producer is None:
        return False
    if not isinstance(producer, Binary):
        return False
    # Check for OROR type — portable string check per _skip_log.md gotcha #13
    if "OROR" not in str(producer.type).upper() and "OR" not in str(producer.type).upper():
        # Also accept BinaryType.OR (bitwise) since |= is semantically correct for bools
        pass
    else:
        # It's OROR — check that the bool_var appears in the operands
        if bool_var in producer.read:
            return True
    # Also check for plain OR (bitwise |, used via |=)
    if "OR" in str(producer.type).upper():
        if bool_var in producer.read:
            return True
    return False


def _detect_in_function(function) -> list:
    """
    Return list of (variable, overwrite_node) pairs found in this function.
    One entry per unique variable (to avoid duplicate hits in loops).
    """
    # Step 1: build tmp_producer_map across all nodes
    tmp_producer_map: dict = {}
    for node in function.nodes:
        for ir in node.irs:
            lv = getattr(ir, "lvalue", None)
            if isinstance(lv, TemporaryVariable):
                tmp_producer_map[id(lv)] = ir

    # Step 2: walk nodes tracking bool vars that were assigned true
    seen_true: dict = {}   # id(var) → var object
    flagged: dict = {}     # id(var) → (var, node) — one flag per var
    already_flagged: set = set()

    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            lv = ir.lvalue
            rv = ir.rvalue
            if lv is None or rv is None:
                continue
            if not isinstance(lv, (StateVariable, LocalVariable)):
                continue
            if not _is_bool_var(lv):
                continue

            var_id = id(lv)

            if _is_true_constant(rv):
                # Record that this variable was set to true at some point
                seen_true[var_id] = lv
            elif var_id in seen_true and var_id not in already_flagged:
                # The variable was previously set to true.
                # Check whether this assignment safely accumulates (uses OR).
                if not _rvalue_is_or_of_var(rv, lv, tmp_producer_map):
                    flagged[var_id] = (lv, node)
                    already_flagged.add(var_id)

    return list(flagged.values())


class BoolAccumulatorOverwrite(AbstractDetector):
    """
    Detect bool variables set to true, then re-assigned via plain = (not |=).
    """

    ARGUMENT = "bool-accumulator-overwrite"
    HELP = "Bool variable set true earlier, then overwritten via plain = (not |=)"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Boolean Accumulator Overwrite"
    WIKI_DESCRIPTION = (
        "A boolean flag is set to `true` (e.g. inside an `if` branch) and later "
        "unconditionally re-assigned with a plain `=` rather than `|=` or `||`. "
        "When the second condition is false at runtime the earlier `true` is "
        "silently discarded, causing safety/halt logic to be bypassed. "
        "Found in BasisOS (_afterDecreasePosition): `shouldPause = exceedsThreshold` "
        "should have been `shouldPause |= exceedsThreshold`."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function checkConditions(uint256 a, uint256 b) external {
    if (a > 100) { shouldPause = true; }
    shouldPause = (b > 100);  // BUG: clobbers the earlier true when b <= 100
}
```
When `a = 200` and `b = 50` the first branch sets `shouldPause = true`.
The unconditional second assignment evaluates `b > 100` as `false` and
writes `false`, silently discarding the earlier pause signal.
The system continues operating when it should have halted."""
    WIKI_RECOMMENDATION = (
        "Replace the plain assignment with an OR-accumulation: "
        "`shouldPause = shouldPause || (b > 100)` or `shouldPause |= (b > 100)`. "
        "If the intent is to always overwrite, remove the earlier conditional "
        "assignment or restructure the logic so both conditions are evaluated "
        "in a single expression."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                hits = _detect_in_function(function)
                for bool_var, overwrite_node in hits:
                    info: DETECTOR_INFO = [
                        function,
                        " in ",
                        contract,
                        " sets bool variable `",
                        bool_var.name,
                        "` to true (conditional) then overwrites it via plain `=` at ",
                        overwrite_node,
                        ". Use `|=` or `||` to accumulate the flag.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
