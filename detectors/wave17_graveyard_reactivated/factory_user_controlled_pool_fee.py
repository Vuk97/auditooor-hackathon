"""
factory_user_controlled_pool_fee.py - Custom Slither detector.

Pattern (IQ AI M-01, slice_ab): A pool / pair factory function takes a
user-supplied `fee` parameter and forwards it straight into a new pool's
constructor, without validating the value against a whitelist or a
governance-controlled bound. An attacker can front-run legitimate
deployments and squat the canonical pair with a malicious fee tier
(typically 0 or 10 000 bps), permanently steering liquidity through a
pool they control.

Detection strategy:
    1. Find external/public functions whose name matches
       `create(Pool|Pair)` / `deploy(Pool|Pair)`.
    2. The function must accept at least one unsigned-integer parameter
       whose name contains `fee` / `tier`.
    3. The function must contain a `NewContract` IR that USES that fee
       parameter as one of its arguments (direct pass-through).
    4. No node in the function must use the fee parameter inside a
       `require`/`if`:
         a) as an Index into a state-var mapping (whitelist lookup), OR
         b) as the left/right of a Binary comparison (bound check).
    5. If (3) and (4) both hold → flag.

@author auditooor wave11
@pattern slice_ab IQ AI M-01 factory user-controlled pair fee
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
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import Binary, Index, NewContract
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_FACTORY_FN_RE = re.compile(r"^(create|deploy).*(pool|pair)", re.IGNORECASE)
_FEE_PARAM_RE = re.compile(r"(fee|tier)", re.IGNORECASE)


def _is_unsigned_int_type(tp) -> bool:
    s = str(tp).lower()
    return s.startswith("uint")


class FactoryUserControlledPoolFee(AbstractDetector):
    """Pair/pool factory forwards a caller-supplied fee without validation."""

    ARGUMENT = "factory-user-controlled-pool-fee"
    HELP = (
        "createPool/createPair takes a user `fee` parameter, passes it to "
        "`new Pool(...)` constructor, never validates against a whitelist"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Factory Creates Pool With Unvalidated User Fee"
    WIKI_DESCRIPTION = (
        "A pool / pair factory takes a `fee` argument and forwards it to "
        "the new pool's constructor without checking it against a "
        "whitelist of allowed fee tiers or an admin-controlled bound. "
        "Anyone can front-run canonical pool deployment and squat the "
        "address with a malicious fee (0 bps or adversarial high). "
        "Reported in IQ AI M-01."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function createPool(address t0, address t1, uint24 fee) external {
    bytes32 key = keccak256(abi.encode(t0, t1, fee));
    require(getPool[key] == address(0));
    getPool[key] = address(new Pool(t0, t1, fee)); // BUG: no fee whitelist
}
```
The attacker watches the mempool, front-runs a protocol's pool
deployment, and seeds the canonical pair at a zero-fee or adversarial
tier. Router-generated keys now point at the attacker's pool."""
    WIKI_RECOMMENDATION = (
        "Maintain a governance-controlled mapping of allowed fee tiers "
        "(à la Uniswap V3 `feeAmountTickSpacing`) and require("
        "allowed[fee]) before deployment, or restrict the factory to an "
        "admin role entirely."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                if not function.name or not _FACTORY_FN_RE.search(function.name):
                    continue

                fee_params = [
                    p for p in function.parameters
                    if isinstance(p, LocalVariable)
                    and p.name
                    and _FEE_PARAM_RE.search(p.name)
                    and _is_unsigned_int_type(getattr(p, "type", ""))
                ]
                if not fee_params:
                    continue

                # (3) Fee param must be used in a NewContract IR.
                new_node = None
                passed_fee_params = set()
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, NewContract):
                            continue
                        args = list(getattr(ir, "arguments", []) or [])
                        for fp in fee_params:
                            if fp in args:
                                passed_fee_params.add(fp)
                                if new_node is None:
                                    new_node = node
                if not passed_fee_params:
                    continue

                # (4) No validation: for each passed fee param, look for a
                # require/if node that either Indexes a mapping with it or
                # uses it in a Binary compare.
                def _has_validation(fp):
                    for node in function.nodes:
                        if not (node.contains_require_or_assert() or node.contains_if()):
                            continue
                        if fp not in (node.local_variables_read or []):
                            continue
                        for ir in node.irs:
                            if isinstance(ir, Index):
                                rv = getattr(ir, "variable_right", None)
                                if rv is fp:
                                    return True
                            elif isinstance(ir, Binary):
                                lv = ir.variable_left
                                rv = ir.variable_right
                                if lv is fp or rv is fp:
                                    return True
                    return False

                unvalidated = [fp for fp in passed_fee_params if not _has_validation(fp)]
                if not unvalidated:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " deploys a new pool via `new` at ",
                    new_node,
                    " and forwards user-supplied fee parameter `",
                    (unvalidated[0].name or "?"),
                    "` without checking it against a whitelist or bound.\n",
                ]
                results.append(self.generate_result(info))

        return results
