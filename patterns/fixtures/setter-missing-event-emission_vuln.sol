// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: privileged setters mutate critical state without emitting any event.
// Off-chain indexers / dashboards / monitoring cannot track these changes.

contract SilentGovernedVuln {
    address public owner;
    address public feeReceiver;
    address public oracle;
    uint256 public feeBps;
    uint256 public rate;

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

    // VULN 1: setter mutates state, no emit.
    function setFeeReceiver(address newReceiver) external onlyOwner {
        feeReceiver = newReceiver;
    }

    // VULN 2: setter mutates state, no emit.
    function setOracle(address newOracle) external onlyAdmin {
        oracle = newOracle;
    }

    // VULN 3: update* naming.
    function updateFeeBps(uint256 newFee) external onlyGovernance {
        feeBps = newFee;
    }

    // VULN 4: change* naming.
    function changeRate(uint256 newRate) external onlyOwner {
        rate = newRate;
    }
}
