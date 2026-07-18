// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IYieldAdapterC {
    function unwrap(uint256 amount, uint256 minOut, address recipient) external returns (uint256);
    function price() external view returns (uint256); // 1e18-scaled
}

contract AlchemistClean {
    struct Account { uint256 collateral; uint256 debt; }
    mapping(address => Account) public accounts;
    uint256 public minimumCollateralization = 2e18;
    address public yieldTokenAdapter;

    function liquidate(uint256 amount, uint256 minimumAmountOut) external returns (uint256 credited) {
        Account storage A = accounts[msg.sender];
        require(A.collateral >= amount, "dust col");
        // Enforce protocol-level slippage floor.
        uint256 oracleOut = (amount * IYieldAdapterC(yieldTokenAdapter).price()) / 1e18;
        require(minimumAmountOut >= (oracleOut * 95) / 100, "slippage");
        A.collateral -= amount;
        credited = IYieldAdapterC(yieldTokenAdapter).unwrap(amount, minimumAmountOut, address(this));
        if (credited >= A.debt) { A.debt = 0; } else { A.debt -= credited; }
        _validate(msg.sender);
    }

    function _validate(address who) internal view {
        Account memory A = accounts[who];
        if (A.debt == 0) return;
        uint256 ratio = (A.collateral * 1e18) / A.debt;
        require(ratio >= minimumCollateralization, "undercollateralised");
    }
}
