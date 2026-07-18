"""
Fixture-smoke detector for
`erc20permit-and-erc20-name-mismatch-causes-eip712-signature-failure`.

Reactivated from the old wave13 graveyard row after KLBQ-005 showed the
fixture pair and focused unittest were healthy but the only runnable detector
required `--include-graveyard`.

Detection strategy:
1. Walk non-vendored contracts that inherit both `ERC20` and `ERC20Permit`.
2. Inspect the constructor source for base-constructor calls.
3. Extract the first `ERC20(...)` name argument and the `ERC20Permit(...)`
   name argument when both are string literals.
4. Flag the contract when the two literals differ, because the token's
   EIP-712 permit domain will not match the ERC20-visible name.

This is intentionally a fixture-smoke approximation. It does not resolve
identifiers, constants, or forwarded constructor parameters, so the row remains
`NOT_SUBMIT_READY`.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")
_ERC20_INHERITANCE = re.compile(r"\bERC20\b")
_PERMIT_INHERITANCE = re.compile(r"\bERC20Permit\b")
_STRING_LITERAL = r'"(?:\\.|[^"\\])*"'
_ERC20_LITERAL_NAME = re.compile(
    rf"\bERC20\s*\(\s*(?P<name>{_STRING_LITERAL})\s*,",
    re.DOTALL,
)
_PERMIT_LITERAL_NAME = re.compile(
    rf"\bERC20Permit\s*\(\s*(?P<name>{_STRING_LITERAL})\s*\)",
    re.DOTALL,
)


def _source_text(obj) -> str:
    source_mapping = getattr(obj, "source_mapping", None)
    if source_mapping and source_mapping.content:
        return source_mapping.content
    return ""


def _inherits_relevant_bases(contract) -> bool:
    names = {base.name for base in getattr(contract, "inheritance", [])}
    if "ERC20" in names and "ERC20Permit" in names:
        return True

    source = _source_text(contract)
    return bool(_ERC20_INHERITANCE.search(source) and _PERMIT_INHERITANCE.search(source))


def _constructor_name_literals(contract) -> tuple[str, str] | None:
    constructor = getattr(contract, "constructor", None)
    constructor_source = _source_text(constructor)
    if not constructor_source:
        constructor_source = _source_text(contract)
    if not constructor_source:
        return None

    erc20_match = _ERC20_LITERAL_NAME.search(constructor_source)
    permit_match = _PERMIT_LITERAL_NAME.search(constructor_source)
    if not erc20_match or not permit_match:
        return None

    return erc20_match.group("name"), permit_match.group("name")


class Erc20permitAndErc20NameMismatchCausesEip712SignatureFailure(AbstractDetector):
    ARGUMENT = "erc20permit-and-erc20-name-mismatch-causes-eip712-signature-failure"
    HELP = "ERC20 and ERC20Permit use different constructor name literals, breaking permit signatures"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc20permit-and-erc20-name-mismatch-causes-eip712-signature-failure.yaml"
    WIKI_TITLE = "ERC20Permit and ERC20 name mismatch breaks EIP-712 permit signatures"
    WIKI_DESCRIPTION = (
        "OpenZeppelin-style `ERC20Permit` derives its EIP-712 domain name from "
        "the permit constructor argument. If the token separately initializes "
        "`ERC20` with a different name literal, user wallets sign against the "
        "visible ERC20 name while on-chain permit verification hashes a "
        "different domain."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A token deploys with `ERC20(\"TokenA\", \"TKA\")` but "
        "`ERC20Permit(\"TokenB\")`. Wallets and integrators read `name()` as "
        "`TokenA`, generate a permit signature for that domain, and every "
        "on-chain `permit` call reverts because the contract validates against "
        "`TokenB` instead."
    )
    WIKI_RECOMMENDATION = (
        "Pass the same token name to `ERC20` and `ERC20Permit`, or derive both "
        "from the same constructor parameter."
    )

    def _detect(self):
        results = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(keyword in contract.name.lower() for keyword in _SKIP_KEYWORDS):
                continue
            if not _inherits_relevant_bases(contract):
                continue

            names = _constructor_name_literals(contract)
            if names is None:
                continue

            erc20_name, permit_name = names
            if erc20_name == permit_name:
                continue

            anchor = getattr(contract, "constructor", None) or contract
            info = [
                anchor,
                " initializes `ERC20` with name literal ",
                erc20_name,
                " but `ERC20Permit` with ",
                permit_name,
                "; the EIP-712 permit domain will not match the token name "
                "exposed by ERC20 and signatures can fail.\n",
            ]
            results.append(self.generate_result(info))

        return results
