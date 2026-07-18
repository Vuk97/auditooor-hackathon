"""
clone_constructor_bypass.py - Custom Slither detector.

ARG: clone-constructor-bypass
IMPACT: HIGH
CONFIDENCE: MEDIUM

Pattern (P25): EIP-1167 minimal proxy clones do NOT execute the implementation's
constructor. When an implementation contract has non-zero inline state-variable
initializers (e.g. `uint256 public feePercent = 50`) and is deployed via
Clones.clone()/ClonesUpgradeable.clone()/LibClone.clone(), every clone's storage
starts zeroed. Unless an `initialize()` / `__init()` function re-applies all the
defaults after cloning, the clone operates with incorrect zero values.

This is subtly different from `missing-disableInitializers` (which targets UUPS
implementations not calling _disableInitializers in constructor). This detector
focuses on the CLONED IMPLEMENTATION having inline defaults that are silently
dropped.

Source: reference/corpus_mined/slice_af.md - Lido Fixed Income audit. VaultFactory
clones LidoVault; minimumDepositAmount = 0.01 ether ends up as 0 in clones.

IR patterns used (verified on fixture):
  - `slitherConstructorVariables` function in the implementation holds
    `Assignment | stateVar := <nonzero Constant>` IRs for each inline default.
  - Factory/caller contract has a `LibraryCall` with dest name matching
    CLONE_LIB_NAMES (Clones / ClonesUpgradeable / LibClone) and function name
    "clone" or "cloneDeterministic".
  - The lvalue of the LibraryCall is an address-typed variable that is the
    newly created clone. We track what contract type it comes from (the argument).
  - Clean: implementation has an `initialize` function (or any function starting
    with `initialize` / `__init`) that writes to those same state vars.

@author auditooor wave6
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
from slither.slithir.operations import LibraryCall, HighLevelCall, Assignment, TypeConversion
from slither.slithir.variables import Constant, TemporaryVariable
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Library names that perform EIP-1167 clone deployments.
CLONE_LIB_NAMES = {"Clones", "ClonesUpgradeable", "LibClone", "MinimalProxyFactory"}
# Function names in those libraries that return a new clone address.
CLONE_FUNC_NAMES = {"clone", "cloneDeterministic", "deployClone"}

# Functions in the implementation that are acceptable re-initializers.
# Any function whose name starts with one of these is treated as an initializer.
INIT_PREFIXES = ("initialize", "__init", "_init")


def _get_nonzero_inline_defaults(contract):
    """
    Return the set of StateVariable names that have non-zero inline initializers.

    Slither compiles inline initializers into a synthetic function called
    `slitherConstructorVariables`. Each `Assignment` IR in that function
    whose lvalue is a StateVariable is an inline default.

    We track the set of TemporaryVariable ids whose value ultimately comes from
    a non-zero Constant (via TypeConversion IR). This handles both:
      1. `uint256 x = 50`   → Assignment(lvalue=x, rvalue=Constant(50))
      2. `address y = 0xDEAD` → TypeConversion(lvalue=TMP, ...) +
                                  Assignment(lvalue=y, rvalue=TMP)

    Any Assignment where:
    - lvalue is StateVariable
    - rvalue is a non-zero Constant OR a TemporaryVariable derived from a
      non-zero Constant (via TypeConversion)
    → flag the state variable as having a non-zero inline default.
    """
    sv_names: set[str] = set()
    for f in contract.functions_and_modifiers_declared:
        if f.name != "slitherConstructorVariables":
            continue

        # First pass: track TemporaryVariable ids that come from non-zero constants
        # via TypeConversion (handles address casts like `address(0xDEAD)`).
        nonzero_tmp_ids: set[int] = set()
        for node in f.nodes:
            for ir in node.irs:
                if isinstance(ir, TypeConversion):
                    # TypeConversion.variable is the source operand.
                    src = getattr(ir, "variable", None)
                    if src is None:
                        # fallback: check ir.read
                        for r in ir.read:
                            if isinstance(r, Constant) and _is_nonzero_constant(r):
                                lv = getattr(ir, "lvalue", None)
                                if lv is not None:
                                    nonzero_tmp_ids.add(id(lv))
                    elif isinstance(src, Constant) and _is_nonzero_constant(src):
                        lv = getattr(ir, "lvalue", None)
                        if lv is not None:
                            nonzero_tmp_ids.add(id(lv))

        # Second pass: find Assignment IRs writing to StateVariables with
        # non-zero values (Constant or TemporaryVariable from above).
        for node in f.nodes:
            for ir in node.irs:
                if not isinstance(ir, Assignment):
                    continue
                lv = ir.lvalue
                if not isinstance(lv, StateVariable):
                    continue
                rv = getattr(ir, "rvalue", None)
                if rv is None:
                    # Fallback: check ir.read for Constants or known non-zero TMPs
                    for r in ir.read:
                        if isinstance(r, Constant) and _is_nonzero_constant(r):
                            sv_names.add(lv.name)
                            break
                        if isinstance(r, TemporaryVariable) and id(r) in nonzero_tmp_ids:
                            sv_names.add(lv.name)
                            break
                elif isinstance(rv, Constant) and _is_nonzero_constant(rv):
                    sv_names.add(lv.name)
                elif isinstance(rv, TemporaryVariable) and id(rv) in nonzero_tmp_ids:
                    sv_names.add(lv.name)
    return sv_names


def _is_nonzero_constant(c: Constant) -> bool:
    """Return True if the Constant is not the zero/false/empty default."""
    try:
        val = c.value
        if val is None:
            return False
        if isinstance(val, bool):
            return val  # False is the zero default
        if isinstance(val, int):
            return val != 0
        if isinstance(val, str):
            return val not in ("", "0x0000000000000000000000000000000000000000")
        # For other types, treat as non-zero if not 0
        return str(val) not in ("0", "False", "false", "0x0", "")
    except Exception:
        return False


def _has_initializer_function(contract) -> bool:
    """
    Return True if the contract declares a function whose name starts with
    an INIT_PREFIX (initialize / __init / _init) and that function writes
    to at least one state variable.
    """
    for f in contract.functions_and_modifiers_declared:
        name_lower = f.name.lower()
        if not any(name_lower.startswith(p) for p in INIT_PREFIXES):
            continue
        # Must actually write at least one state variable to qualify.
        if f.state_variables_written:
            return True
    return False


def _get_contract_name_from_new_contract(ir) -> str:
    """
    Extract the string contract name from a NewContract IR.
    In Slither, NewContract.contract_name is a UserDefinedType object;
    `str()` on it yields the contract name string directly.
    """
    cn = getattr(ir, "contract_name", None)
    if cn is None:
        return ""
    return str(cn)


def _collect_cloned_impl_addresses(all_contracts):
    """
    Walk all functions in all contracts looking for LibraryCall to clone
    functions (Clones.clone, ClonesUpgradeable.clone, etc.).

    Returns a set of contract NAMES (strings) that are used as the
    implementation argument to clone().

    Strategy: within any factory contract (one that both calls clone() AND
    deploys contracts via `new X()`), the contracts deployed via NewContract
    IR are considered implementation candidates. This covers the common
    pattern: `implementation = address(new LidoVault()); Clones.clone(impl)`.

    The scan is codebase-wide: if ANY contract in the compilation unit calls
    Clones.clone() and also deploys X via `new X()`, then X is considered
    cloned. This is an over-approximation but avoids false negatives where
    the factory stores the implementation in a state variable set in the
    constructor and the clone call is in a different function.
    """
    from slither.slithir.operations import NewContract as _NewContract

    # Per-contract: track clone presence and new-contract deployments
    # across ALL functions (not just the same function).
    contract_clones: dict[str, bool] = {}  # contract.name -> has_clone_call
    contract_news: dict[str, set] = {}  # contract.name -> set of impl names deployed

    for contract in all_contracts:
        has_clone = False
        new_names: set[str] = set()
        for f in contract.functions_and_modifiers_declared:
            for node in f.nodes:
                for ir in node.irs:
                    if isinstance(ir, LibraryCall):
                        dest = ir.destination
                        dest_name = dest if isinstance(dest, str) else getattr(dest, "name", "")
                        func = ir.function
                        func_name = getattr(func, "name", getattr(func, "function_name", ""))
                        if dest_name in CLONE_LIB_NAMES and func_name in CLONE_FUNC_NAMES:
                            has_clone = True
                    if isinstance(ir, _NewContract):
                        name = _get_contract_name_from_new_contract(ir)
                        if name:
                            new_names.add(name)
        contract_clones[contract.name] = has_clone
        contract_news[contract.name] = new_names

    # Collect impl names for all factory contracts that have clone calls.
    cloned_contract_names: set[str] = set()
    for cname, has_clone in contract_clones.items():
        if has_clone:
            cloned_contract_names.update(contract_news.get(cname, set()))

    return cloned_contract_names


class CloneConstructorBypass(AbstractDetector):
    """
    Detect implementation contracts that are EIP-1167 cloned but have
    non-zero inline state-variable initializers without an initialize()
    function - clone storage starts zeroed, constructor never runs.
    """

    ARGUMENT = "clone-constructor-bypass"
    HELP = "Cloned contract has inline state-var defaults not re-applied in initialize()"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "EIP-1167 Clone Constructor Bypass - Inline Defaults Not Applied"
    WIKI_DESCRIPTION = (
        "EIP-1167 minimal proxy clones copy the implementation's bytecode but do NOT "
        "execute the constructor. State variables with inline initializers "
        "(e.g. `uint256 public feePercent = 50`) are set in the constructor on the "
        "implementation contract, but in every clone those slots remain zero. If the "
        "cloned contract has no `initialize()` function that explicitly re-applies all "
        "inline defaults, the clone operates with incorrect zero values. Observed in the "
        "Lido Fixed Income audit: `VaultFactory` clones `LidoVault` whose "
        "`minimumDepositAmount = 0.01 ether` silently becomes 0 in all clones."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract LidoVault {
    uint256 public minimumDepositAmount = 0.01 ether;  // set by constructor, NOT by clone
    function deposit() external payable {
        require(msg.value >= minimumDepositAmount, "too small");  // always passes (0 >= 0)
    }
}
contract VaultFactory {
    function createVault() external returns (address) {
        return Clones.clone(address(implementation));
        // minimumDepositAmount is 0 in the clone - 0-ETH deposits accepted
    }
}
```
Attacker calls `deposit()` on a clone with `msg.value == 0`. The require passes
because `minimumDepositAmount` was never set (still 0). Protocol logic that
depends on non-zero minimums is bypassed."""
    WIKI_RECOMMENDATION = (
        "Add an `initialize()` function to the implementation that explicitly sets "
        "every inline default, and call it immediately after `Clones.clone()` in the "
        "factory. Remove or keep-but-document the inline initializer values as "
        "documentation-only. Alternatively, use a pattern like OpenZeppelin "
        "Initializable that enforces post-clone initialization."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        all_contracts = self.contracts

        # Step 1: find all contract names used as implementation in clone() calls.
        cloned_names = _collect_cloned_impl_addresses(all_contracts)

        # Step 2: for each contract whose name is in cloned_names, check:
        #   a. Has non-zero inline defaults?
        #   b. Does NOT have an initialize() function that writes state?
        for contract in all_contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if contract.name not in cloned_names:
                continue

            inline_defaults = _get_nonzero_inline_defaults(contract)
            if not inline_defaults:
                continue  # no non-zero inline defaults - not vulnerable

            if _has_initializer_function(contract):
                continue  # has initializer - clean

            # Vulnerable: cloned contract with inline defaults and no initializer.
            sv_list = ", ".join(sorted(inline_defaults))
            info: DETECTOR_INFO = [
                "Contract ",
                contract,
                " is deployed via EIP-1167 clone() but has non-zero inline state-variable "
                "initializers [" + sv_list + "] with no initialize() function. "
                "Clone storage starts zeroed - constructor never runs on clones.",
            ]
            results.append(self.generate_result(info))

        return results
