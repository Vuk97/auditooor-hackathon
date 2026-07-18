"""
pps_max_zero_underflow_masking.py - Custom Slither detector.

Pattern (Sukuk M-03, slice_ad): A price-per-share / NAV computation guards
against `liabilities > assets` by returning `0` instead of reverting. This
masks insolvency: a vault that is in-debt reports `pps == 0` and depositors
continue minting shares at a conversion rate of zero, instantly losing their
principal.

Detection strategy:
    Scan view/pure-style functions whose names match a price-per-share
    pattern (`pps`, `pricePerShare`, `sharePrice`, `convertToAssets`,
    `convertToShares`). Walk their IR - flag if the body contains an IF
    whose condition is `assets > liabilities` (or `>=`, or `<` swapped)
    and whose false-branch returns a constant 0.

@author auditooor wave9
@pattern slice_ad Sukuk M-03
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
from slither.slithir.operations import Binary, BinaryType, Return, Condition
from slither.slithir.variables import Constant
from slither.core.cfg.node import NodeType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_PPS_RE = re.compile(
    r"^(pps|priceperShare|sharePrice|convertToAssets|convertToShares|"
    r"getRate|getPricePerShare|exchangeRate)$",
    re.IGNORECASE,
)

_COMPARISON_TYPES = frozenset({
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
})


def _condition_is_solvency_check(node) -> bool:
    """Heuristic: the IF condition is a comparison between two operands and
    at least one of them looks like an "assets/liabilities" pair."""
    has_comparison = False
    for ir in node.irs:
        if isinstance(ir, Binary) and ir.type in _COMPARISON_TYPES:
            has_comparison = True
            break
    if not has_comparison:
        return False
    # Pull variable names mentioned in this node's expression.
    expr = str(node.expression or "").lower()
    mentions_assets = any(k in expr for k in ("asset", "balance", "totalassets"))
    mentions_liab = any(k in expr for k in ("liab", "debt", "borrow", "owed"))
    return mentions_assets and mentions_liab


def _find_son_returning_zero(node):
    """Walk forward from an IF node along its FALSE successor and return the
    first RETURN node whose returned value is a constant 0. We follow up to
    a few hops to skip ENDIF / placeholder nodes."""
    if not node.sons:
        return None
    # In Slither, IF nodes have son_true (index 0) and son_false (index 1).
    # When one branch is empty the false-branch is the post-if join, so we
    # walk both branches looking for `return 0` reachable without leaving
    # the if-construct.
    visited = set()
    stack = list(node.sons)
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in visited:
            continue
        visited.add(id(cur))
        if len(visited) > 8:
            break
        for ir in cur.irs:
            if isinstance(ir, Return):
                for v in ir.values:
                    if isinstance(v, Constant) and v.value in (0, "0"):
                        return cur
        # Follow a single son along the chain (skip past ENDIF nodes).
        if cur.type in (NodeType.ENDIF, NodeType.OTHER_ENTRYPOINT):
            stack.extend(cur.sons)
    return None


class PpsMaxZeroUnderflowMasking(AbstractDetector):
    """Detect price-per-share functions that mask insolvency by returning 0
    when liabilities exceed assets."""

    ARGUMENT = "pps-max-zero-underflow-masking"
    HELP = (
        "pricePerShare/convertTo* returns 0 when liabilities > assets - "
        "masks insolvency, depositors mint shares at rate zero"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Price-Per-Share Masks Insolvency With Zero Return"
    WIKI_DESCRIPTION = (
        "A price-per-share / convertTo* function that returns `0` instead of "
        "reverting when liabilities exceed assets silently hides a vault's "
        "insolvency. Depositors continue minting shares against the vault and "
        "their `convertToShares(amount)` either reverts on the divide-by-zero "
        "or mints an unbounded number of shares. Either way, depositors lose "
        "their principal because the vault is already in the red. The correct "
        "behaviour is to revert and refuse new deposits until the vault is "
        "recapitalised."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function pricePerShare() external view returns (uint256) {
    if (assets > liabilities) {
        return ((assets - liabilities) * 1e18) / shares;
    }
    return 0;   // BUG: hides insolvency
}
```
1. Vault takes a loss, liabilities now exceed assets.
2. `pricePerShare()` returns 0.
3. Alice deposits 1000 USDC. `convertToShares()` either reverts on
   divide-by-zero or mints 0 shares; the protocol still keeps Alice's USDC.
4. Alice's principal is gone."""
    WIKI_RECOMMENDATION = (
        "Revert (e.g. `require(assets >= liabilities, \"insolvent\")`) "
        "instead of returning 0. Pause deposits when the vault is in the red."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                if function.is_constructor:
                    continue
                if not _PPS_RE.match(function.name or ""):
                    continue

                # Walk IF nodes; flag when the condition is a solvency check
                # and one branch returns constant 0.
                for node in function.nodes:
                    if node.type != NodeType.IF:
                        continue
                    if not _condition_is_solvency_check(node):
                        continue
                    zero_node = _find_son_returning_zero(node)
                    if zero_node is None:
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " in ",
                        contract,
                        " masks insolvency at ",
                        node,
                        ": when liabilities exceed assets the function "
                        "returns 0 (",
                        zero_node,
                        ") instead of reverting - depositors keep minting "
                        "against an in-debt vault.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # one hit per function

        return results
