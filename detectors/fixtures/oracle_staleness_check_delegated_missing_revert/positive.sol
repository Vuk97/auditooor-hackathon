// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - oracle-staleness-check-delegated-missing-revert
// VULN: borrow() computes block.timestamp - obs.updatedAt (age) but never checks
// that age <= MAX_STALENESS. The stale price propagates into borrow calculation.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IAggregator {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

contract VulnPriceConsumer {
    IAggregator public oracle;
    IERC20 public collateral;
    IERC20 public debt;
    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public debtBalance;

    // VULN: computes age but no require enforcing age <= threshold.
    function borrow(uint256 amount) external {
        (, int256 answer, , uint256 updatedAt, ) = oracle.latestRoundData();
        uint256 age = block.timestamp - updatedAt; // computed but not checked
        uint256 price = uint256(answer);
        uint256 collateralValue = collateralBalance[msg.sender] * price / 1e8;
        require(collateralValue >= amount * 150 / 100, "insufficient collateral");
        // stale price used for borrow - no revert on age
        debtBalance[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }

    function deposit(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralBalance[msg.sender] += amount;
    }
}
