"""
create2_factory_non_idempotent.py - Custom Slither detector.

Pattern (Sequence M-04 / ERC-4337, slice_ad): A wallet/account factory's
`createAccount(owner, salt)` deploys via CREATE2 but does NOT first check if
the deterministic address already has code. ERC-4337 bundlers expect the
factory to be idempotent - calling twice with identical params should return
the existing deployment, not revert. A non-idempotent factory either reverts
on the second call (waste of bundler gas, failed UserOp) or - worse - silently
fails with a contract-already-exists revert that the bundler treats as a
configuration error.

Detection strategy:
    1. Function name matches /(create|deploy).*(Account|Wallet|Contract)/.
    2. Function contains a `NewContract` SlithIR op with `call_salt` set
       (i.e. CREATE2 - `new X{salt: s}(...)`).
    3. Function does NOT contain a `CodeSize` IR (which models both
       `address.code.length` and inline-assembly `extcodesize`). The
       canonical idempotent pattern reads code size of the predicted
       address before deploying.

@author auditooor wave9
@pattern slice_ad Sequence M-04
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
from slither.slithir.operations import NewContract
from slither.slithir.operations.codesize import CodeSize
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_FACTORY_NAME_RE = re.compile(
    r"(create|deploy).*(account|wallet|contract|proxy|clone)",
    re.IGNORECASE,
)


def _function_has_code_size_check(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, CodeSize):
                return True
    return False


class Create2FactoryNonIdempotent(AbstractDetector):
    """Flag CREATE2-based account factories that do not check for an
    existing deployment before deploying."""

    ARGUMENT = "create2-factory-non-idempotent"
    HELP = (
        "ERC-4337 / wallet factory deploys via CREATE2 without checking if "
        "the deterministic address already exists; second call reverts"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Non-Idempotent CREATE2 Account Factory"
    WIKI_DESCRIPTION = (
        "ERC-4337 spec requires that calling a wallet factory with the same "
        "(owner, salt) twice MUST return the existing deployment, not revert. "
        "A factory that just calls `new Wallet{salt: s}(owner)` without first "
        "checking `predicted.code.length == 0` reverts on the second call, "
        "breaking bundler retry logic and failing UserOps. (Sequence M-04.)"
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function createAccount(address owner, bytes32 salt) external returns (Wallet) {
    return new Wallet{salt: salt}(owner); // BUG: no idempotency check
}
```
A bundler retries a UserOp after a brief delay. The retry calls the factory
with the same (owner, salt). The CREATE2 reverts because the address already
has code, and the bundler marks the wallet as un-deployable."""
    WIKI_RECOMMENDATION = (
        "Predict the CREATE2 address, check `predicted.code.length == 0` (or "
        "`extcodesize(predicted)` in assembly); return the existing deployment "
        "if it has code, otherwise deploy. See the ERC-4337 reference factory."
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
                name = function.name or ""
                if not _FACTORY_NAME_RE.search(name):
                    continue

                # Find the CREATE2 NewContract IR (call_salt set).
                create2_node = None
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, NewContract) and getattr(ir, "call_salt", None) is not None:
                            create2_node = node
                            break
                    if create2_node is not None:
                        break
                if create2_node is None:
                    continue

                if _function_has_code_size_check(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " deploys via CREATE2 at ",
                    create2_node,
                    " without first checking that the deterministic address is "
                    "empty - second call with the same salt reverts, breaking "
                    "ERC-4337 bundler idempotency.\n",
                ]
                results.append(self.generate_result(info))

        return results
