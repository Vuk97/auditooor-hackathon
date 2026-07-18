// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - oracle-staleness-check-delegated-missing-revert
// CLEAN: borrow() computes age AND requires age <= MAX_STALENESS before using price.

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

contract CleanPriceConsumer {
    IAggregator public oracle;
    IERC20 public collateral;
    IERC20 public debt;
    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public debtBalance;

    uint256 public constant MAX_STALENESS = 1 hours;

    // CLEAN: staleness check enforced inline in the consuming function.
    function borrow(uint256 amount) external {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = oracle.latestRoundData();
        // Enforce freshness inline - revert if stale.
        require(block.timestamp - updatedAt <= MAX_STALENESS, "StaleOracle");
        require(answeredInRound >= roundId, "StaleRound");
        require(answer > 0, "InvalidPrice");
        uint256 price = uint256(answer);
        uint256 collateralValue = collateralBalance[msg.sender] * price / 1e8;
        require(collateralValue >= amount * 150 / 100, "insufficient collateral");
        debtBalance[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }

    function deposit(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralBalance[msg.sender] += amount;
    }
}
