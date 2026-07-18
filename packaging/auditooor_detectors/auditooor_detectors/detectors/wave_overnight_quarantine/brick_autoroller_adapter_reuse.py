import re
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _is_roller_deploying_contract(contract) -> bool:
    contract_name_lower = contract.name.lower()
    if "roller" in contract_name_lower or "factory" in contract_name_lower:
        return True
    return False


def _has_create_function_with_roller_new(contract):
    for function in contract.functions:
        if function.name != "create":
            continue
        # Check if function body contains 'new Roller' or 'new AutoRoller'
        for node in function.nodes:
            for ir in node.irs:
                expr_str = str(ir).lower()
                if ("new roller" in expr_str or "new autoroller" in expr_str or
                    "newauto" in expr_str.replace(" ", "")):
                    return function
        # Also check source_str for new expressions as fallback
        if function.source_mapping and function.source_mapping.content:
            content = function.source_mapping.content.lower()
            if "new roller" in content or "new autoroller" in content:
                return function
    return None


def _has_adapter_roller_mapping(contract) -> bool:
    for sv in contract.state_variables_declared:
        if sv.mapping_key_type is None:
            continue
        var_name = (sv.name or "").lower()
        if "adapter" in var_name and ("roller" in var_name or "factory" in var_name):
            return True
    return False


def _has_require_adapter_check(contract, create_function) -> bool:
    if create_function is None:
        return False
    for node in create_function.nodes:
        for ir in node.irs:
            expr_str = str(ir).lower()
            if "require" in expr_str and "adapter" in expr_str:
                return True
    return False


class BrickAutorollerAdapterReuse(AbstractDetector):
    """Detect factories deploying AutoRoller contracts without adapter uniqueness protection."""

    ARGUMENT = "brick-autoroller-adapter-reuse"
    HELP = "Factory creates AutoRoller without checking if adapter already has a roller"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/brick-autoroller-adapter-reuse.yaml"
    WIKI_TITLE = "AutoRoller Factory Adapter Reuse Vulnerability"
    WIKI_DESCRIPTION = (
        "Factory contracts that deploy Roller/AutoRoller instances must ensure "
        "each adapter address maps to a unique roller. Without a tracking mapping "
        "and a require check, the same adapter can be reused across multiple "
        "deployments, causing the factory to overwrite previous state and potentially "
        "lose track of deployed rollers and their associated pools."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract AutoRollerFactory {
    address[] public rollers;
    function create(IAdapter adapter) external returns (address roller) {
        // MISSING: require(!adapterToRoller[adapter], "Already exists");
        // MISSING: mapping to track adapter -> roller
        roller = address(new AutoRoller(adapter));
    }
}
```
An attacker calls `create(adapter)` twice with the same adapter. The second
call deploys a new AutoRoller but the factory has no record of the first one.
Sponsorship and maturity tracking become corrupted across series."""
    WIKI_RECOMMENDATION = (
        "Add a mapping(address => address) adapterToRoller and a require check "
        "before deployment to prevent adapter reuse."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if not _is_roller_deploying_contract(contract):
                continue

            create_func = _has_create_function_with_roller_new(contract)
            if create_func is None:
                continue

            has_mapping = _has_adapter_roller_mapping(contract)
            has_require_check = _has_require_adapter_check(contract, create_func)

            if not has_mapping and not has_require_check:
                info: DETECTOR_INFO = [
                    contract,
                    " deploys Roller/AutoRoller via create() but lacks both "
                    "adapter-to-roller mapping and require check. The same adapter "
                    "can be used multiple times, corrupting roller tracking.\n",
                ]
                results.append(self.generate_result(info))
            elif not has_mapping:
                info: DETECTOR_INFO = [
                    contract,
                    " deploys Roller/AutoRoller via create() but lacks an "
                    "adapter-to-roller mapping. Cannot prevent adapter reuse.\n",
                ]
                results.append(self.generate_result(info))
            elif not has_require_check:
                info: DETECTOR_INFO = [
                    contract,
                    " deploys Roller/AutoRoller via create() but lacks a require "
                    "check preventing adapter reuse before deployment.\n",
                ]
                results.append(self.generate_result(info))

        return results