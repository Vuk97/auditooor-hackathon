"""
same_entropy_seed_multiple_outputs.py - Custom Slither detector.

Pattern (Megapot M-05, slice_ad): A draw / lottery / game function uses
one entropy seed to derive multiple independent random outputs (e.g. the
normal ball AND the bonus ball) by directly modulo'ing the same seed
value. Because every output is a pure function of a single shared seed,
the outputs are perfectly correlated - knowing one reveals the others.
The correct pattern is to hash the seed with a distinct domain tag per
output (`keccak256(seed, "ball1")` vs `keccak256(seed, "bonus")`).

Detection strategy:
    1. Iterate every declared function that takes at least one parameter
       whose name matches `(seed|entropy|random|rand|randomness|nonce)`.
    2. Count the number of Binary MODULO IRs whose operand (left or right)
       is literally that seed parameter.
    3. If the count is >= 2 AND each modulo result feeds a DIFFERENT
       state variable assignment, flag - multiple outputs share the same
       raw seed without domain separation.

@author auditooor wave11
@pattern slice_ad Megapot M-05
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
from slither.slithir.operations import Binary, BinaryType, Assignment
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_SEED_RE = re.compile(
    r"^(seed|entropy|random|rand|randomness|nonce|rawseed|vrfresult)$",
    re.IGNORECASE,
)


def _is_seed_var(v) -> bool:
    nm = getattr(v, "name", None) or ""
    return bool(_SEED_RE.match(nm))


class SameEntropySeedMultipleOutputs(AbstractDetector):
    """Flag single entropy seed reused (raw) to derive multiple random outputs."""

    ARGUMENT = "same-entropy-seed-multiple-outputs"
    HELP = (
        "Single entropy seed reused raw to derive multiple independent "
        "random outputs - outputs become perfectly correlated"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Same Entropy Seed Used For Multiple Random Outputs"
    WIKI_DESCRIPTION = (
        "A draw function derives multiple random outputs (e.g. the normal "
        "ball and the bonus ball of a lottery, or multiple winners of a "
        "raffle) by modulo'ing the SAME raw entropy seed. Because every "
        "output is a deterministic function of the single shared seed, "
        "the outputs are perfectly correlated - once the seed is known "
        "or guessed, all outputs are revealed. Domain-separate each "
        "output with its own `keccak256(seed, tag)` hash. "
        "Source: Megapot M-05 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function drawBalls(uint256 entropy) external {
    normalBall = entropy % 69;              // BUG: raw seed
    bonusBall  = entropy % 26;              // same raw seed
}
```
1. The lottery promises independent odds across normal + bonus balls.
2. Both outputs are pure functions of the same `entropy` - they are
   perfectly correlated. An attacker able to influence the draw can
   engineer a single value that satisfies both winning conditions.
3. Even without manipulation, the stated odds (1/69 × 1/26) are wrong."""
    WIKI_RECOMMENDATION = (
        "Derive each output from a domain-separated hash of the seed: "
        "`uint256(keccak256(abi.encode(seed, \"ball1\"))) % 69`, "
        "`uint256(keccak256(abi.encode(seed, \"bonus\"))) % 26`. Do not "
        "use the raw seed as the operand of multiple modulo operations."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor or function.view or function.pure:
                    continue
                seed_params = [p for p in (function.parameters or []) if _is_seed_var(p)]
                if not seed_params:
                    continue
                seed_names = {p.name for p in seed_params}

                # Walk IRs; for each MODULO Binary whose operand is the
                # seed, remember its tmp lvalue, then look for Assignments
                # of that tmp into state variables.
                mod_tmps = []
                state_writes_from_seed = set()
                state_vars_touched = []
                for node in function.nodes:
                    local_mod_tmps = []
                    for ir in node.irs:
                        if isinstance(ir, Binary) and ir.type == BinaryType.MODULO:
                            operands = (ir.variable_left, ir.variable_right)
                            if any(
                                getattr(v, "name", None) in seed_names for v in operands
                            ):
                                local_mod_tmps.append(ir.lvalue)
                                mod_tmps.append(ir.lvalue)
                        if isinstance(ir, Assignment) and ir.rvalue in mod_tmps:
                            # lvalue should be a state variable
                            lv = ir.lvalue
                            if lv in function.contract.state_variables:
                                state_writes_from_seed.add(lv.name)
                                state_vars_touched.append(lv)

                if len(state_writes_from_seed) < 2:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " derives multiple state outputs (",
                    ", ".join(sorted(state_writes_from_seed)),
                    ") from a single raw entropy seed parameter. Domain-"
                    "separate each output via `keccak256(seed, tag)` to "
                    "decorrelate them.\n",
                ]
                results.append(self.generate_result(info))

        return results
