import re
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


class ArrayCollateralListManipulation(AbstractDetector):
    ARGUMENT = "array-collateral-list-manipulation"
    HELP = "Array parameters processed in loops without length validation or deduplication"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/array-collateral-list-manipulation.yaml"
    WIKI_TITLE = "Array Collateral List Manipulation"
    WIKI_DESCRIPTION = """
Detects functions that process multiple array parameters in loops without:
1. Length validation between the iterated array and accessed array
2. Deduplication checks to prevent duplicate processing

This can lead to out-of-bounds access if arrays have mismatched lengths,
or state corruption if duplicate entries are processed multiple times.
"""
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function liquidate(address[] calldata tokens, uint256[] calldata minAmountsOut) external {
    // No length check between tokens and minAmountsOut
    for (uint256 i = 0; i < tokens.length; i++) {
        collateralBalances[tokens[i]] -= minAmountsOut[i];
    }
}
```
An attacker can pass `tokens` with length 10 but `minAmountsOut` with length 1,
causing out-of-bounds access when `i >= 1`.
"""
    WIKI_RECOMMENDATION = "Add require(array1.length == array2.length) before loops and use mapping-based deduplication when processing user-provided arrays."

    def _has_length_validation(self, function: Function, array_names: list) -> bool:
        for node in function.nodes:
            node_code = str(node).lower()
            if "require" in node_code or "assert" in node_code:
                for arr1 in array_names:
                    for arr2 in array_names:
                        if arr1 in node_code and arr2 in node_code and "==" in node_code:
                            return True
        return False

    def _has_deduplication(self, function: Function, array_names: list) -> bool:
        for node in function.nodes:
            node_code = str(node).lower()
            if "memory" in node_code and "seen" in node_code:
                return True
            if "require(!seen" in node_code:
                return True
            if "require(!_" in node_code and ("duplicate" in node_code or "already" in node_code):
                return True
        return False

    def _has_state_write_in_loop(self, function: Function, array_params: list) -> bool:
        loop_nodes = []
        for node in function.nodes:
            if node.is_empty():
                continue
            if node.is_loops():
                loop_nodes.append(node)

        for loop_node in loop_nodes:
            for child in loop_node.sons:
                self._collect_loop_body_nodes(child, loop_node, function, array_params)

        return False

    def _collect_loop_body_nodes(self, node, loop_entry, function, array_params):
        if node == loop_entry:
            return
        for ir in node.irs:
            if hasattr(ir, 'destination') and ir.destination:
                sv = ir.destination
                if hasattr(sv, 'is_state_variable') and sv.is_state_variable:
                    return True
        for child in node.sons:
            if self._collect_loop_body_nodes(child, loop_entry, function, array_params):
                return True
        return False

    def _check_function(self, function: Function) -> bool:
        if function.is_constructor or function.is_fallback or function.is_receive:
            return False
        if function.is_read_only:
            return False

        array_params = []
        for param in function.parameters:
            param_type = str(param.type)
            param_name = param.name
            if "[]" in param_type and param_name:
                array_params.append(param.name.lower())

        if len(array_params) < 2:
            return False

        has_length_validation = self._has_length_validation(function, array_params)
        has_dedup = self._has_deduplication(function, array_params)

        if has_length_validation and has_dedup:
            return False

        has_loop = False
        for node in function.nodes:
            if node.is_loops():
                has_loop = True
                break

        if not has_loop:
            return False

        vulnerable_loop_found = False
        for node in function.nodes:
            if not node.is_loops():
                continue

            node_str = str(node).lower()
            for arr_iter in array_params:
                if arr_iter + ".length" in node_str or arr_iter + " .length" in node_str:
                    for arr_access in array_params:
                        if arr_access != arr_iter and "[" + arr_access + "[" in node_str:
                            vulnerable_loop_found = True
                            break
                    if vulnerable_loop_found:
                        break

            if vulnerable_loop_found:
                break

        return vulnerable_loop_found and not (has_length_validation and has_dedup)

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        skip_keywords = ["test", "mock", "fixture", "helper", "script", "setup", "deploy"]

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in skip_keywords):
                continue

            for function in contract.functions:
                if self._check_function(function):
                    info: DETECTOR_INFO = [
                        function,
                        " processes multiple array parameters in a loop without length validation or deduplication. "
                        "This can lead to out-of-bounds access or duplicate processing.\n",
                    ]
                    results.append(self.generate_result(info))

        return results