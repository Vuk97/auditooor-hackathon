"""
modifier_precedes_initializer.py - Custom Slither detector.

ARG: modifier-precedes-initializer
SEVERITY: MEDIUM  CONFIDENCE: LOW

Pattern (P24 from reference/corpus_mined/slice_ad.md - Concrete "FeeBeforeInit"):

  A function modifier reads a state variable X that is ONLY initialized inside
  the function body (lazy init). Because modifiers execute BEFORE the function
  body, on the very first call the modifier reads X == 0 (the EVM zero-default)
  rather than the intended initial value.

  Concrete shape:
      uint256 public feesUpdatedAt;          // not set in constructor

      modifier takeFees() {
          uint256 age = block.timestamp - feesUpdatedAt;  // reads feesUpdatedAt
          uint256 fee = age * rate;                        // HUGE fee on first call
          _;
      }

      function deposit(uint256 amt) external takeFees {
          feesUpdatedAt = block.timestamp;   // writes feesUpdatedAt (lazy init)
      }

  On first call: modifier reads feesUpdatedAt = 0 → age = block.timestamp ≈ 1.7e9
  → massive fee. Body then sets feesUpdatedAt = now → second call is correct.

Detection logic:
  1. For each non-constructor, non-view, non-pure function F:
     a. Collect the set of state variables READ by any of F's modifiers.
     b. Collect the set of state variables WRITTEN by F's own function body
        (F.state_variables_written, which Slither computes from the CFG).
     c. Intersection = vars written by F AND read by a modifier.
     d. For each intersecting var V: check whether the constructor writes V.
        If the constructor DOES write V, it was not lazily initialized → skip.
     e. If V is NOT written in the constructor → flag.

  2. Emit one result per (function, modifier, var) triple that satisfies
     all conditions.

Key IR notes (from _skip_log.md and verified against existing detectors):
  - function.modifiers   → list of Modifier objects (each has .nodes, .state_variables_read, etc.)
  - function.state_variables_written → set/list of StateVariable written in the entire function
  - modifier.state_variables_read    → all StateVariables read in the modifier
  - constructor.state_variables_written → StateVariables initialized in the constructor

Gotchas:
  - function.modifiers returns Modifier objects; they expose .nodes, .state_variables_read
    directly as high-level aggregated lists (not just raw IR).
  - The constructor is found via contract.constructor (may be None for contracts
    without an explicit constructor).
  - Keep CONFIDENCE LOW: there are real false positives (e.g. when the lazy init
    is intentionally inside the function body and the modifier is designed to
    handle zero gracefully).

Dedup: `slither --list-detectors | grep -iE "modifier|init"` → only
  `incorrect-modifier` (#59 LOW, modifiers returning default value),
  `function-init-state` (#81, informational), `uninitialized-state` (#13,
  vars never written anywhere). None catches the modifier-reads-before-body-init
  pattern. NOVEL.

Source: reference/corpus_mined/slice_ad.md - Concrete finding "FeeBeforeInit"
@author auditooor wave6
@pattern P24 modifier-precedes-initializer
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
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# State variable name substrings that indicate a lazily-initialized timestamp
# or counter whose zero-default causes corrupt fee/rate math in a modifier.
# These are the "dangerous when zero" variable classes.
_LAZY_INIT_HINTS = (
    "updatedat",
    "updated_at",
    "timestamp",
    "lasttimestamp",
    "last_timestamp",
    "lastupdated",
    "last_updated",
    "lastaccrue",
    "last_accrue",
    "accrueat",
    "accruedat",
    "accrued_at",
    "feetime",
    "fee_time",
    "feeupdated",
    "fee_updated",
    "interesttime",
    "interest_time",
    "lastprice",
    "last_price",
    "lastrate",
    "last_rate",
    "checkpoint",
    "lastsettled",
    "last_settled",
    "settleat",
    "lastblock",
    "last_block",
)


def _looks_like_lazy_init_var(sv: StateVariable) -> bool:
    """
    Return True if the variable name matches a pattern that is problematic
    when read as 0 (timestamps, rate-update markers, accrue-time vars).
    Case-insensitive substring match.
    """
    name = (sv.name or "").lower().replace("_", "")
    return any(hint.replace("_", "") in name for hint in _LAZY_INIT_HINTS)


def _constructor_written_vars(contract) -> set:
    """
    Return the set of StateVariable objects written by this contract's
    constructor, or an empty set if there is no explicit constructor.
    """
    ctor = contract.constructor
    if ctor is None:
        return set()
    # state_variables_written is a list/set of StateVariable
    return set(ctor.state_variables_written)


def _modifier_read_vars(modifier) -> set:
    """
    Return the set of StateVariable objects read anywhere in the modifier body.
    Uses the high-level aggregated attribute (same approach as function.state_variables_read).
    """
    # Slither aggregates state_variables_read at the function/modifier level
    svread = getattr(modifier, "state_variables_read", None)
    if svread is not None:
        return set(v for v in svread if isinstance(v, StateVariable))
    # Fallback: walk nodes manually
    result = set()
    for node in modifier.nodes:
        for v in node.state_variables_read:
            if isinstance(v, StateVariable):
                result.add(v)
    return result


def _function_body_written_vars(function) -> set:
    """
    Return the set of StateVariable objects written in the function body.
    We use function.state_variables_written, which includes the full CFG.
    """
    return set(v for v in function.state_variables_written
               if isinstance(v, StateVariable))


class ModifierPrecedesInitializer(AbstractDetector):
    """
    Detect modifiers that read a state variable only initialized inside the
    decorated function body (lazy init). First call: modifier reads zero.
    """

    ARGUMENT = "modifier-precedes-initializer"
    HELP = (
        "Modifier reads a state variable that is only initialized inside the "
        "function body (lazy init); first call reads zero"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Modifier Precedes Lazy Initializer"
    WIKI_DESCRIPTION = (
        "A function modifier reads a state variable X that is only set to its "
        "meaningful value inside the function body (lazy initialization). Because "
        "modifiers execute BEFORE the function body in Solidity, on the very first "
        "call to the decorated function the modifier sees X == 0 (EVM default) "
        "instead of the intended value. This causes incorrect behaviour on the first "
        "invocation - for example, a fee modifier computing `block.timestamp - "
        "feesUpdatedAt` when feesUpdatedAt == 0 yields an astronomically large "
        "duration and a correspondingly large fee. Found in Concrete (Zellic audit, "
        "FeeBeforeInit)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public feesUpdatedAt;   // NOT set in constructor

modifier takeFees() {
    uint256 age = block.timestamp - feesUpdatedAt;  // reads 0 on first call
    uint256 fee = age * 1e15;
    totalAssets -= fee;          // catastrophic fee on first deposit
    _;
}

function deposit(uint256 amt) external takeFees {
    feesUpdatedAt = block.timestamp;  // lazy init happens AFTER modifier
    totalAssets += amt;
}
```
On the first call to `deposit()` the `takeFees` modifier executes with
`feesUpdatedAt == 0`, producing `age ≈ 1.7 × 10^9` seconds.  The inflated
fee is deducted before any assets are deposited, draining or reverting the
vault.  All subsequent calls are correct because `feesUpdatedAt` is now set."""
    WIKI_RECOMMENDATION = (
        "Initialize the state variable in the constructor (or in an initializer "
        "called from the constructor) so that modifiers always see a meaningful "
        "value.  For example: `constructor() { feesUpdatedAt = block.timestamp; }`. "
        "Alternatively restructure so the lazy-init write happens BEFORE the fee "
        "computation, e.g. by inlining the modifier logic."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            # Compute state vars initialized in the constructor once per contract
            ctor_written = _constructor_written_vars(contract)

            for function in contract.functions_and_modifiers_declared:
                # Only consider regular functions (not constructors, not modifiers
                # themselves, not view/pure - lazy init only matters in state-mutating fns)
                if function.is_constructor:
                    continue
                if type(function).__name__ == "Modifier":
                    continue
                if function.view or function.pure:
                    continue

                # Need at least one modifier that reads state vars
                modifiers = function.modifiers
                if not modifiers:
                    continue

                # State vars written in this function body
                fn_written = _function_body_written_vars(function)
                if not fn_written:
                    continue

                for modifier in modifiers:
                    mod_reads = _modifier_read_vars(modifier)
                    if not mod_reads:
                        continue

                    # Intersection: vars the modifier reads AND the function writes
                    overlap = mod_reads & fn_written

                    for sv in overlap:
                        # Skip if constructor already initializes this var
                        if sv in ctor_written:
                            continue

                        # Narrow to timestamp/counter-like variable names:
                        # only vars whose zero-default causes corrupt math.
                        if not _looks_like_lazy_init_var(sv):
                            continue

                        # Flag: modifier reads sv, function body writes sv (lazy init),
                        # and constructor does NOT pre-initialize sv.
                        info: DETECTOR_INFO = [
                            function,
                            " in ",
                            contract,
                            " has modifier `",
                            modifier.name,
                            "` that reads state variable ",
                            sv,
                            " which is only written inside the function body"
                            " (lazy init). On the first call the modifier sees"
                            " `" + sv.name + "` == 0 before the body sets it.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
