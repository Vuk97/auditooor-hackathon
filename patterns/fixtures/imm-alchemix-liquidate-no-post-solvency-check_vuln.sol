// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IYieldAdapter {
    function unwrap(uint256 amount, uint256 minOut, address recipient) external returns (uint256);
}

contract AlchemistVuln {
    struct Account { uint256 collateral; uint256 debt; }
    mapping(address => Account) public accounts;
    uint256 public minimumCollateralization = 2e18; // 200%
    address public yieldTokenAdapter;

    // VULN: liquidate reduces collateral via _unwrap with user-supplied
    // minOut and never re-checks solvency afterward.
    function liquidate(uint256 amount, uint256 minimumAmountOut) external returns (uint256 credited) {
        Account storage A = accounts[msg.sender];
        require(A.collateral >= amount, "dust col");
        A.collateral -= amount;
        credited = IYieldAdapter(yieldTokenAdapter).unwrap(amount, minimumAmountOut, address(this));
        // Credit collapses debt.
        if (credited >= A.debt) {
            A.debt = 0;
        } else {
            A.debt -= credited;
        }
        // Missing: _validate(account) — collateral/debt ratio not checked.
    }
}
