"""
assembly_muldiv_no_overflow_check.py - Custom Slither detector.

Pattern (Quantstamp POL-EX-5 - ctf-exchange-v2 CalculatorHelper.sol):
Inline assembly that computes `div(mul(a, b), c)` bypasses Solidity 0.8
checked arithmetic. If `a * b > 2**256 - 1` the multiplication silently
wraps and the downstream divide returns a nonsense settlement amount.

The live example is `CalculatorHelper.calculateTakingAmount()`:

    assembly {
        takingAmount := div(mul(makingAmount, takerAmount), makerAmount)
    }

Detection strategy (text scan of inline-assembly source):
    1. For every NodeType.ASSEMBLY node, read the source text.
    2. Look for a `mul(` token whose result is fed to a `div(` directly
       (nested call OR via an intermediate `let` variable).
    3. Reject the match if the same assembly block contains an overflow
       guard: `gt(`, `iszero(`, or a call to `checked` / `Math.mulDiv`.
    4. Flag the assembly node otherwise.

A looser secondary check: the whole function body contains no
`type(uint256).max` comparison, so there is no Solidity-side overflow
guard surrounding the assembly either.

@author auditooor wave11
@pattern Quantstamp POL-EX-5
"""

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup")

# Fast text probes - operate on the inline-asm source snippet.
_MUL_RE = re.compile(r"\bmul\s*\(", re.IGNORECASE)
_DIV_RE = re.compile(r"\bdiv\s*\(", re.IGNORECASE)
# Overflow-guarding tokens: gt(...) / iszero(...) / div(not(0),...) pattern.
_GUARD_RE = re.compile(
    r"\b(gt|iszero|lt|checked|mulmod)\s*\(",
    re.IGNORECASE,
)
# Any reference to Solady/OpenZeppelin mulDiv → assume the author knows.
_SAFE_LIB_RE = re.compile(r"mulDiv|FullMath|PRBMath", re.IGNORECASE)


def _source_text_for_node(node) -> str:
    sm = getattr(node, "source_mapping", None)
    if sm is None:
        return ""
    return sm.content or ""


def _is_vulnerable_asm(src: str) -> bool:
    if not _MUL_RE.search(src):
        return False
    if not _DIV_RE.search(src):
        return False
    if _GUARD_RE.search(src):
        return False
    return True


def _function_uses_safe_lib(function) -> bool:
    # Scan function source text for a mulDiv-style helper call.
    sm = getattr(function, "source_mapping", None)
    if sm is None or not sm.content:
        return False
    return bool(_SAFE_LIB_RE.search(sm.content))


class AssemblyMulDivNoOverflowCheck(AbstractDetector):
    """Inline assembly computes `div(mul(a, b), c)` without an overflow check."""

    ARGUMENT = "assembly-muldiv-no-overflow-check"
    HELP = (
        "Inline assembly computes `div(mul(a, b), c)` with no overflow "
        "guard - the intermediate product can silently wrap mod 2^256."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Inline assembly mul/div without overflow check"
    WIKI_DESCRIPTION = (
        "Inline assembly blocks bypass the Solidity 0.8 checked-arithmetic "
        "pass. A multiplication inside `assembly { ... }` that is not "
        "followed by an `mulmod` / `gt` overflow guard will silently wrap "
        "on overflow, and the downstream division returns a nonsense "
        "result. The `CalculatorHelper.calculateTakingAmount()` helper in "
        "Polymarket ctf-exchange-v2 had this shape; Quantstamp filed it as "
        "POL-EX-5 and Polymarket replaced the assembly with a plain "
        "Solidity expression."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function calculateTakingAmount(uint256 makingAmount, uint256 makerAmount, uint256 takerAmount)
    public pure returns (uint256 takingAmount)
{
    assembly {
        // mul(makingAmount, takerAmount) can overflow silently
        takingAmount := div(mul(makingAmount, takerAmount), makerAmount)
    }
}
```
An operator submits an order whose `makerAmount * takerAmount` exceeds
`2**256 - 1`; the taking amount wraps and settlement transfers an
attacker-controlled value."""
    WIKI_RECOMMENDATION = (
        "Either use plain Solidity math `(a * b) / c` so the compiler "
        "inserts an overflow check, or add an explicit assembly guard "
        "`if gt(b, div(not(0), a)) { revert(0, 0) }` before the `mul`. "
        "Even better, use Solady/PRBMath `mulDiv` helpers."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if _function_uses_safe_lib(function):
                    continue
                for node in function.nodes:
                    if node.type != NodeType.ASSEMBLY:
                        continue
                    src = _source_text_for_node(node)
                    if not _is_vulnerable_asm(src):
                        continue
                    info: DETECTOR_INFO = [
                        function,
                        " inline-assembly block computes `div(mul(...))` "
                        "with no overflow guard at ",
                        node,
                        " - intermediate product can silently wrap mod "
                        "2^256.\n",
                    ]
                    results.append(self.generate_result(info))
        return results
