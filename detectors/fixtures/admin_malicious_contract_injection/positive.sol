// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - admin-malicious-contract-injection
// VULN: setOracle accepts arbitrary address with no non-zero check,
// no code-size check, no interface validation, no timelock.

interface IOracle {
    function getPrice() external view returns (uint256);
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnLendingPool {
    IOracle public oracle;
    IERC20 public collateral;
    IERC20 public debt;
    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public debtBalance;
    address public owner;

    // VULN: no zero-address check, no code-size check, no timelock
    function setOracle(address _oracle) external onlyOwner {
        oracle = IOracle(_oracle);
    }

    function deposit(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralBalance[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 price = oracle.getPrice();
        uint256 collateralValue = collateralBalance[msg.sender] * price / 1e18;
        require(collateralValue >= amount * 150 / 100, "insufficient collateral");
        debtBalance[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }

    // price manipulation path => bad liquidations
    function liquidate(address borrower) external {
        uint256 price = oracle.getPrice();
        uint256 collateralValue = collateralBalance[borrower] * price / 1e18;
        require(collateralValue < debtBalance[borrower], "healthy");
        collateral.transfer(msg.sender, collateralBalance[borrower]);
        collateralBalance[borrower] = 0;
        debtBalance[borrower] = 0;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}
