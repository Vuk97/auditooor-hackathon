import re
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output
from slither.core.expressions import CallExpression, MemberAccess
from slither.core.variables.state_variable import StateVariable


# Keywords that indicate non-user (test/vendored) contracts
_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# Vault-related name patterns
_VAULT_NAME_RE = re.compile(
    r"(^|.*[_/])(vault|softVault|hardVault|lpVault|strategyVault)$",
    re.IGNORECASE,
)

# Functions that convert vault shares → underlying assets (anti-pattern exclusion)
_CONVERSION_FUNCTIONS = {
    "converttoassets",
    "previewredeem",
    "converttoshares",
    "previewdeposit",
}


def _is_vault_variable(expr, contract) -> bool:
    """Return True if expr references a vault-type variable."""
    if hasattr(expr, "value") and expr.value:
        name = getattr(expr.value, "name", "") or getattr(expr.value, "canonical_name", "")
        if _VAULT_NAME_RE.search(name):
            return True
    if isinstance(expr, CallExpression):
        callee = expr.called
        if isinstance(callee, MemberAccess):
            var_name = getattr(callee.expression, "name", "")
            if _VAULT_NAME_RE.search(var_name):
                return True
    return False


def _is_balance_of_call(node, contract) -> bool:
    """Return (vault_expr, result_var) if node is vault.balanceOf(...) pattern."""
    for ir in node.irs:
        if not hasattr(ir, "expression"):
            continue
        expr = ir.expression
        if not isinstance(expr, CallExpression):
            continue
        callee = expr.called
        if not isinstance(callee, MemberAccess):
            continue
        member_name = getattr(callee, "member_name", "") or ""
        if member_name.lower() != "balanceof":
            continue
        vault_expr = callee.expression
        if _is_vault_variable(vault_expr, contract):
            return (vault_expr, None)
    return (None, None)


def _is_convert_wrapper(result_node) -> bool:
    """Return True if result_node is immediately wrapped by a conversion call."""
    if not hasattr(result_node, "irs") or not result_node.irs:
        return False
    ir = result_node.irs[0]
    if not hasattr(ir, "expression"):
        return False
    expr = ir.expression
    if not isinstance(expr, CallExpression):
        return False
    callee = expr.called
    if not isinstance(callee, MemberAccess):
        return False
    member_name = getattr(callee, "member_name", "") or ""
    return member_name.lower() in _CONVERSION_FUNCTIONS


def _find_vault_balance_uses(function, contract) -> list:
    """
    Walk function nodes looking for vault.balanceOf() results
    that are misused in collateral accounting.
    Returns list of problematic function nodes.
    """
    findings = []
    balance_nodes = []

    for node in function.nodes:
        for ir in node.irs:
            if not hasattr(ir, "expression"):
                continue
            expr = ir.expression
            if not isinstance(expr, CallExpression):
                continue
            callee = getattr(expr, "called", None)
            if not isinstance(callee, MemberAccess):
                continue
            member_name = getattr(callee, "member_name", "") or ""
            if member_name.lower() != "balanceof":
                continue
            vault_expr = getattr(callee, "expression", None)
            if vault_expr and _is_vault_variable(vault_expr, contract):
                balance_nodes.append((node, vault_expr))

    for bal_node, vault_expr in balance_nodes:
        if _is_convert_wrapper(bal_node):
            continue
        for node in function.nodes:
            for ir in node.irs:
                if not hasattr(ir, "expression"):
                    continue
                expr = ir.expression
                if not isinstance(expr, (CallExpression, AssignmentOperation, BinaryOperation)):
                    continue
                if hasattr(ir, "variables_read") or hasattr(ir, "call_list"):
                    if bal_node in function.nodes:
                        if _related_to_collateral(node):
                            findings.append(node)
                            break

    return findings


def _related_to_collateral(node) -> bool:
    """Check if node involves collateral accounting patterns."""
    node_str = str(node).lower()
    collateral_indicators = [
        "collateral",
        "position",
        "deposit",
        "borrow",
        "liab",
        "obligation",
    ]
    for indicator in collateral_indicators:
        if indicator in node_str:
            return True
    return False


class BlueberryBankVaultBalanceAccountingMismatch(AbstractDetector):
    """Detect vault.balanceOf() results used directly as collateral without conversion."""

    ARGUMENT = "blueberry-bank-vault-balance-accounting-mismatch"
    HELP = (
        "Vault share balance used as collateral/position value without "
        "convertToAssets conversion — will corrupt accounting on vault "
        "rebasing or fee-on-transfer scenarios"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-balanceof-collateral-mismatch.yaml"
    WIKI_TITLE = "Blueberry Bank Vault Balance Accounting Mismatch"
    WIKI_DESCRIPTION = (
        "Blueberry-style lending protocols track user collateral using vault share "
        "balances (e.g. from Yearn-style Vaults) instead of the underlying asset "
        "equivalent. When vault shares are used directly in collateral/position "
        "accounting without calling convertToAssets() first, any vault operation "
        "that changes the share price (rebasing, fee-on-transfer, yield accrual) "
        "will silently corrupt the protocol's accounting — user positions will "
        "be valued at stale or incorrect amounts, leading to undercollateralized "
        "borrowing, incorrect liquidation thresholds, or drained pools.\n"
        "The bug manifests in five patterns: (1) openPosition records vault shares "
        "as collateral amount; (2) depositAndRecordCollateral adds vault.balanceOf "
        "instead of convertToAssets(shares); (3) withdrawCollateral checks vault "
        "balance instead of collateral[user]; (4) getLiquidCollateral returns share "
        "balance; (5) takeCollateral subtracts share balance from collateral mapping."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract VulnerableBank {
    IVault public vault;
    mapping(address => uint256) public collateral;

    function depositAndRecordCollateral(uint256 amount) external {
        vault.deposit(amount, address(this));
        // BUG: vault shares recorded as collateral
        collateral[msg.sender] += vault.balanceOf(address(this));
    }

    function getLiquidCollateral(address user) external view returns (uint256) {
        // BUG: returns vault share balance, not underlying
        return vault.balanceOf(address(this));
    }
}
```
If the vault implements a rebase or fee-on-transfer strategy, the share price
changes but collateral[] still reflects the old share count. A user who deposited
1 ETH when shares=1:1 will have collateral counted as 0.9 ETH after rebase even
though their vault position is worth 1.1 ETH — the protocol will liquidate a
solvent position or allow undercollateralized borrowing."""
    WIKI_RECOMMENDATION = (
        "Use vault.convertToAssets(shares) or vault.previewRedeem(shares) to "
        "convert vault share balances to underlying asset amounts before "
        "recording in collateral mappings or position accounting."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.compilation_units[0].contracts:
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            vault_vars = []
            for sv in contract.state_variables_declared:
                name = getattr(sv, "name", "") or ""
                if _VAULT_NAME_RE.search(name):
                    vault_vars.append(name)

            for function in contract.functions:
                if function.is_constructor or function.is_placeholder:
                    continue

                has_vault_call = False
                balance_of_results = []

                for node in function.nodes:
                    for ir in node.irs:
                        if not hasattr(ir, "expression"):
                            continue
                        expr = ir.expression
                        if not isinstance(expr, CallExpression):
                            continue
                        callee = getattr(expr, "called", None)
                        if not isinstance(callee, MemberAccess):
                            continue
                        member_name = getattr(callee, "member_name", "") or ""
                        if member_name.lower() != "balanceof":
                            continue
                        vault_expr = getattr(callee, "expression", None)
                        if vault_expr is None:
                            continue
                        var_name = getattr(vault_expr, "name", "")
                        if not var_name:
                            continue
                        if any(v in var_name for v in vault_vars) or _VAULT_NAME_RE.search(var_name):
                            has_vault_call = True
                            if not _is_convert_wrapper(node):
                                balance_of_results.append(node)

                if not balance_of_results:
                    continue

                for result_node in balance_of_results:
                    for node in function.nodes:
                        node_str = str(node).lower()
                        collateral_indicators = [
                            "collateral",
                            "position",
                            "deposit",
                            "borrow",
                            "openposition",
                            "takecollateral",
                            "withdrawlend",
                            "addcollateral",
                            "record",
                        ]
                        uses_collateral = any(ind in node_str for ind in collateral_indicators)
                        if uses_collateral and result_node != node:
                            info: DETECTOR_INFO = [
                                function,
                                " uses vault.balanceOf() result directly as collateral/position "
                                "value without convertToAssets conversion. "
                                "This will corrupt accounting if vault shares rebase or accrue fees.\n",
                            ]
                            results.append(self.generate_result(info))
                            break

        return results