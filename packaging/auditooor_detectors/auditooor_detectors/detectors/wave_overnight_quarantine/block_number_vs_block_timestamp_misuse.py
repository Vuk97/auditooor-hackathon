import re
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output
from slither.core.cfg.node import NodeType

_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _is_time_sensitive_function(func) -> bool:
    """
    Check if a function uses block.timestamp or block.number in arithmetic
    or time-sensitive comparisons. Returns True if:
    1. block.* appears in an arithmetic operation (+, -, *, /)
    2. block.* appears in a comparison (<, <=, >, >=) that looks time-related
    """
    block_vars = {"block.timestamp", "block.number"}

    for node in func.nodes:
        # Check expressions in the node
        expr = node.expression
        if expr is not None:
            expr_str = str(expr)

        # Check IR operations (expressions and assignments)
        # Use the node's calls_as_expression to find expressions using block.*
        for call in node.calls_as_expression:
            call_str = str(call)
            if not any(bv in call_str for bv in block_vars):
                continue
            # Found block.timestamp or block.number in expression
            # Check if it's in an arithmetic context
            parent = call.expression if call.expression else None
            if parent and hasattr(parent, 'type'):
                try:
                    if parent.type in (NodeType.BINARY, NodeType.TERNARY):
                        op = str(parent).split()[1] if len(str(parent).split()) > 1 else ""
                        if op in ('+', '-', '*', '/'):
                            return True
                except Exception:
                    pass

        # Check for comparisons with block.*
        for check in node.is_checked:
            check_str = str(check)
            if not any(bv in check_str for bv in block_vars):
                continue
            # Check if this is a time-sensitive comparison (>=, >, <=, <)
            if any(op in check_str for op in ('>=', '>', '<=', '<')):
                return True

    return False


def _has_clock_mode_with_block_pattern(contract) -> bool:
    """
    Check if contract has a CLOCK_MODE function returning a string
    containing 'blocknumber' or 'timestamp' patterns.
    """
    for func in contract.functions:
        if func.name != "CLOCK_MODE":
            continue
        # Check if function returns a string
        if not func.return_types:
            continue
        returns_string = False
        for rt in func.return_types:
            if "string" in str(rt):
                returns_string = True
                break
        if not returns_string:
            continue

        # Scan function body for string literals containing block patterns
        for node in func.nodes:
            for ir in node.irs:
                ir_str = str(ir)
                # Look for string returns that contain blocknumber or timestamp
                if any(p in ir_str.lower() for p in ("blocknumber", "timestamp")):
                    # Verify it's in a string literal context
                    if "'block" in ir_str.lower() or '"block' in ir_str.lower():
                        return True
    return False


def _uses_block_in_arithmetic(func) -> bool:
    """Check if function uses block.timestamp or block.number in arithmetic."""
    block_vars = {"block.timestamp", "block.number"}

    for node in func.nodes:
        # Check node expression string for block.* with arithmetic operators
        node_str = str(node.expression) if node.expression else ""
        if any(bv in node_str for bv in block_vars):
            # Check if any of the arithmetic ops appear near block.*
            for bv in block_vars:
                if bv in node_str:
                    idx = node_str.find(bv)
                    # Look at surrounding context for arithmetic
                    before = node_str[:idx].strip()
                    after = node_str[idx + len(bv):].strip()
                    if before and before[-1] in ('+', '-', '*', '/'):
                        return True
                    if after and after[0] in ('+', '-', '*', '/'):
                        return True

        # Check IRs for binary operations with block.*
        for ir in node.irs:
            ir_str = str(ir)
            if not any(bv in ir_str for bv in block_vars):
                continue
            # Look for binary op with arithmetic
            if hasattr(ir, 'type') and ir.type == NodeType.BINARYOP:
                try:
                    # Get operation from ir
                    if hasattr(ir, 'operation'):
                        op = str(ir.operation)
                        if op in ('+', '-', '*', '/'):
                            return True
                except Exception:
                    pass
            # Direct check for arithmetic pattern in string representation
            if any(f" {op} " in ir_str or f"{op}(" in ir_str for op in ('+', '-', '*', '/')):
                return True

    return False


def _block_used_in_comparison_for_time(contract) -> list:
    """Find functions where block.* is used in time-sensitive comparisons."""
    results = []
    block_vars = {"block.timestamp", "block.number"}
    time_keywords = ("deadline", "delay", "expired", "time", "since", "until", "duration")

    for func in contract.functions:
        found_time_comparison = False
        has_block_in_time_context = False

        for node in func.nodes:
            node_str = str(node.expression) if node.expression else ""

            # Check if this node contains block.* and comparison
            if any(bv in node_str for bv in block_vars):
                # Check for comparison operators
                if any(op in node_str for op in ('>=', '>', '<=', '<')):
                    # Check if function has time-related context
                    func_name_lower = func.name.lower()
                    if any(kw in func_name_lower for kw in time_keywords):
                        has_block_in_time_context = True
                        found_time_comparison = True

        if found_time_comparison and has_block_in_time_context:
            results.append(func)

    return results


class BlockNumberVsBlockTimestampMisuse(AbstractDetector):
    """Detect misuse of block.timestamp and block.number in time-sensitive logic."""

    ARGUMENT = "block-number-vs-block-timestamp-misuse"
    HELP = (
        "Contract uses block.timestamp or block.number directly for "
        "time-sensitive arithmetic or comparisons instead of an oracle"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/block-number-vs-block-timestamp-misuse.yaml"
    WIKI_TITLE = "Block Number vs Block Timestamp Misuse"
    WIKI_DESCRIPTION = (
        "Directly using block.timestamp or block.number for time-sensitive logic "
        "is risky because block.timestamp can be manipulated by miners/validators "
        "within a ~15 second window, and block.number assumes a fixed block time "
        "that may not hold across different chains or chain reorganizations. "
        "For accurate time measurement, a trusted oracle should be used."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function checkProposalExpired() external view returns (bool) {
    return block.timestamp >= proposalDeadline;
}
```
A validator can manipulate block.timestamp to make proposals appear expired
prematurely or extend them beyond intended deadlines."""
    WIKI_RECOMMENDATION = (
        "Use a trusted time oracle instead of direct block.timestamp/block.number "
        "for time-sensitive logic. For example, Chainlink feeds or a custom "
        "sequencer oracle."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            # Skip vendored/test contracts
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Check CLOCK_MODE function for block patterns
            clock_mode_issue = _has_clock_mode_with_block_pattern(contract)

            # Track all issues for this contract
            issues_found = []

            # Check each function for block.* misuse
            for func in contract.functions:
                # Skip internal/private helpers that merely return block values
                if func.visibility in ("internal", "private"):
                    # Only flag if it's part of time-sensitive logic
                    func_str = str(func).lower()
                    if not any(kw in func_str for kw in ("deadline", "delay", "expire", "time", "check")):
                        continue

                # Check for arithmetic with block.*
                if _uses_block_in_arithmetic(func):
                    issues_found.append(f"  - {func.name}: uses block.timestamp/number in arithmetic")

                # Check for time-sensitive comparisons with block.*
                for node in func.nodes:
                    node_expr = str(node.expression) if node.expression else ""
                    block_in_node = "block.timestamp" in node_expr or "block.number" in node_expr

                    if block_in_node:
                        # Check for comparison operators
                        has_comparison = any(op in node_expr for op in ('>=', '>', '<=', '<'))
                        # Check for time-related function context
                        is_time_sensitive = any(
                            kw in func.name.lower()
                            for kw in ("deadline", "expired", "delay", "time", "check", "passed")
                        )
                        if has_comparison and is_time_sensitive:
                            issues_found.append(f"  - {func.name}: block.* in time-sensitive comparison")

            # Also check state variable assignments using block.*
            for sv in contract.state_variables_declared:
                if not sv.expression:
                    continue
                expr_str = str(sv.expression)
                if "block.timestamp" in expr_str or "block.number" in expr_str:
                    # Check if it's part of time-sensitive state
                    sv_name_lower = sv.name.lower()
                    if any(kw in sv_name_lower for kw in ("deadline", "time", "delay", "expiry")):
                        issues_found.append(f"  - state var '{sv.name}': assigned block.* in time context")

            # Report if any issues found or CLOCK_MODE has block pattern
            if issues_found or clock_mode_issue:
                info: DETECTOR_INFO = [
                    contract,
                    " uses block.timestamp or block.number directly for time-sensitive logic.\n",
                ]
                if clock_mode_issue:
                    info.append("  - CLOCK_MODE returns string with 'blocknumber' or 'timestamp' pattern\n")
                for issue in issues_found:
                    info.append(f"{issue}\n")
                info.append(
                    "  Recommendation: Use a trusted oracle abstraction for time measurements.\n"
                )
                results.append(self.generate_result(info))

        return results