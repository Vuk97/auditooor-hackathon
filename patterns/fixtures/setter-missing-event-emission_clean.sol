// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: each privileged setter emits a descriptive event carrying the old
// and new value. Off-chain indexers can reconstruct configuration history.

contract GovernedCleanWithEvents {
    address public owner;
    address public feeReceiver;
    address public oracle;
    uint256 public feeBps;
    uint256 public rate;

    event FeeReceiverUpdated(address indexed previous, address indexed next);
    event OracleUpdated(address indexed previous, address indexed next);
    event FeeBpsUpdated(uint256 previous, uint256 next);
    event RateUpdated(uint256 previous, uint256 next);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == owner, "not admin");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == owner, "not gov");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setFeeReceiver(address newReceiver) external onlyOwner {
        address previous = feeReceiver;
        feeReceiver = newReceiver;
        emit FeeReceiverUpdated(previous, newReceiver);
    }

    function setOracle(address newOracle) external onlyAdmin {
        address previous = oracle;
        oracle = newOracle;
        emit OracleUpdated(previous, newOracle);
    }

    function updateFeeBps(uint256 newFee) external onlyGovernance {
        uint256 previous = feeBps;
        feeBps = newFee;
        emit FeeBpsUpdated(previous, newFee);
    }

    function changeRate(uint256 newRate) external onlyOwner {
        uint256 previous = rate;
        rate = newRate;
        emit RateUpdated(previous, newRate);
    }
}
