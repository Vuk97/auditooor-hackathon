// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VetoQuorumBypassRecallLiftPositive {
    address[] public members;
    uint256 public vetoThresholdBps;
    uint256 public vetoDenominator;
    uint256 public votingPower;
    uint256 public pastSupply;

    struct GovernanceConfig {
        uint256 vetoThresholdBps;
        uint256 vetoDenominator;
        uint256 votingPower;
    }

    GovernanceConfig public governanceConfig;

    event VetoThresholdSet(uint256 previousThreshold, uint256 newThreshold);
    event VotingPowerSet(uint256 previousVotingPower, uint256 newVotingPower);
    event GovernanceConfigSet(
        uint256 previousThreshold,
        uint256 previousDenominator,
        uint256 previousVotingPower,
        uint256 newThreshold,
        uint256 newDenominator,
        uint256 newVotingPower
    );

    constructor() {
        members.push(address(0x1));
        members.push(address(0x2));
        members.push(address(0x3));
        vetoThresholdBps = 5_000;
        vetoDenominator = 10_000;
        votingPower = 3;
        pastSupply = 3;
    }

    function setVetoThreshold(uint256 newThreshold) external {
        uint256 previousThreshold = vetoThresholdBps;
        vetoThresholdBps = newThreshold;
        emit VetoThresholdSet(previousThreshold, newThreshold);
    }

    function setVotingPower(uint256 newVotingPower) external {
        uint256 previousVotingPower = votingPower;
        votingPower = newVotingPower;
        emit VotingPowerSet(previousVotingPower, newVotingPower);
    }

    function setGovernanceConfig(GovernanceConfig calldata newConfig) external {
        GovernanceConfig memory previousConfig = governanceConfig;
        governanceConfig = newConfig;
        vetoThresholdBps = newConfig.vetoThresholdBps;
        vetoDenominator = newConfig.vetoDenominator;
        votingPower = newConfig.votingPower;
        emit GovernanceConfigSet(
            previousConfig.vetoThresholdBps,
            previousConfig.vetoDenominator,
            previousConfig.votingPower,
            newConfig.vetoThresholdBps,
            newConfig.vetoDenominator,
            newConfig.votingPower
        );
    }
}
