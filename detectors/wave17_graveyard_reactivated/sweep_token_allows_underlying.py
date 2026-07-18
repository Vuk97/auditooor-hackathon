"""
sweep_token_allows_underlying.py - Custom Slither detector.

Pattern (slice_ah, Takara Lend - CRITICAL-ish/MEDIUM):
    A `sweepToken`/`rescueToken`/`skimToken` admin helper has an
    INVERTED guard: `require(token == underlying, ...)` instead of
    `require(token != underlying, ...)`. The guard's intention is to
    prevent sweeping of the protocol's primary asset, but the `==`
    comparison instead *only allows* the underlying to be swept,
    letting an admin drain the protocol.

Detection strategy:
    1. Iterate functions_and_modifiers_declared. Keep only those whose
       name matches `sweep|rescue|skim|recover` AND which take at least
       one `address`-typed parameter (`token` / `asset`).
    2. For each such function, scan nodes that are require/assert checks
       (node.contains_require_or_assert()). Inside the node's IR list,
       look for a Binary IR of type EQUAL whose operands are:
         a) the address parameter  (RVALUE)
         b) a state variable whose name contains "underlying", "asset",
            "token", "principal", or "reserve"  (RVALUE)
    3. If any such EQUAL is found → flag. A legitimate clean fix uses
       `NOT_EQUAL`, which this detector ignores.

Confidence: MEDIUM. The function-name allowlist keeps FP rate low; the
restriction to an `==` in a require/assert against an asset-denoting state
variable further narrows it.
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
from slither.core.solidity_types import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, BinaryType, TypeConversion
from slither.utils.output import Output


_SWEEP_NAME_FRAGMENTS = ("sweep", "rescue", "skim", "recover")
_ASSET_STATE_FRAGMENTS = (
    "underlying", "asset", "token", "principal", "reserve", "collateral"
)
_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _has_address_param(function):
    for p in function.parameters:
        tp = p.type
        if isinstance(tp, ElementaryType) and str(tp) == "address":
            return True
    return False


def _is_asset_state_var(v) -> bool:
    if not isinstance(v, StateVariable):
        return False
    name = (v.name or "").lower()
    return any(frag in name for frag in _ASSET_STATE_FRAGMENTS)


class SweepTokenAllowsUnderlying(AbstractDetector):
    """Detect inverted sweep-token guard permitting drain of underlying asset."""

    ARGUMENT = "sweep-token-allows-underlying"
    HELP = (
        "sweepToken/rescueToken guard uses `==` with underlying/asset state "
        "var (should be `!=`), allowing admin to drain the protected asset"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Sweep Token Allows Underlying (Inverted Guard)"
    WIKI_DESCRIPTION = (
        "A sweepToken/rescueToken admin helper is intended to let an operator "
        "recover tokens accidentally sent to the contract WHILE protecting the "
        "protocol's underlying asset. The correct guard is "
        "`require(token != underlying, ...)`. When the operator inadvertently "
        "writes `==`, the helper ONLY permits sweeping of the underlying asset "
        "- the opposite of the intended behaviour - and can be used by the "
        "privileged caller to drain all protocol funds. First observed in "
        "Takara Lend (Zellic audit)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function sweepToken(address token) external onlyOwner {
    require(address(token) == underlying, "only underlying"); // BUG: ==
    IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
}
```
1. Operator calls `sweepToken(underlying)` - the guard passes.
2. All underlying balance is transferred to the caller.
3. Protocol reserves are drained to an EOA."""
    WIKI_RECOMMENDATION = (
        "Invert the guard to `require(token != underlying, ...)` (or similar "
        "for each protected asset). Prefer a stateless allowlist of sweepable "
        "tokens rather than a blacklist."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                fname = (function.name or "").lower()
                if not any(frag in fname for frag in _SWEEP_NAME_FRAGMENTS):
                    continue
                if not _has_address_param(function):
                    continue

                # collect address-typed parameter names for matching
                addr_param_names = {
                    p.name for p in function.parameters
                    if isinstance(p.type, ElementaryType)
                    and str(p.type) == "address"
                }

                flagged = False
                for node in function.nodes:
                    if not node.contains_require_or_assert():
                        continue
                    # Build temp→param taint map within the node:
                    # A `TypeConversion` whose rvalue is an address param
                    # produces a TMP that transitively represents the param.
                    taint_tmps: set = set()
                    for ir in node.irs:
                        if isinstance(ir, TypeConversion):
                            src = getattr(ir, "variable", None)
                            if (
                                src is not None
                                and getattr(src, "name", None) in addr_param_names
                            ):
                                taint_tmps.add(id(ir.lvalue))
                    # Check node's Binary IRs for EQUAL between
                    # (param OR tainted temp) and an asset-denoting SV
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type != BinaryType.EQUAL:
                            continue
                        reads = list(ir.read)
                        has_addr_param = any(
                            getattr(r, "name", None) in addr_param_names
                            or id(r) in taint_tmps
                            for r in reads
                        )
                        has_asset_sv = any(_is_asset_state_var(r) for r in reads)
                        if has_addr_param and has_asset_sv:
                            info: DETECTOR_INFO = [
                                function,
                                " uses an inverted sweep guard (require(token == "
                                "asset)) against state variable - allows admin to "
                                "drain the protocol's protected token. Use `!=`.\n",
                            ]
                            results.append(self.generate_result(info))
                            flagged = True
                            break
                    if flagged:
                        break

        return results
