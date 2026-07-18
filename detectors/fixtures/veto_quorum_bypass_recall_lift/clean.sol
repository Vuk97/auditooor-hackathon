// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VetoQuorumBypassRecallLiftClean {
    uint256 internal constant MIN_VETO_BPS = 5_100;

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
        members.push(address(0x4));
        vetoThresholdBps = 5_000;
        vetoDenominator = 10_000;
        votingPower = 4;
        pastSupply = 4;
    }

    function setVetoThreshold(uint256 newThreshold) external {
        _validateVetoBounds(newThreshold);
        uint256 previousThreshold = vetoThresholdBps;
        vetoThresholdBps = newThreshold;
        emit VetoThresholdSet(previousThreshold, newThreshold);
    }

    function setVotingPower(uint256 newVotingPower) external {
        _validateVotingPower(newVotingPower);
        uint256 previousVotingPower = votingPower;
        votingPower = newVotingPower;
        emit VotingPowerSet(previousVotingPower, newVotingPower);
    }

    function setGovernanceConfig(GovernanceConfig calldata newConfig) external {
        _validateVetoBounds(newConfig.vetoThresholdBps);
        _validateVotingPower(newConfig.votingPower);
        _validateDenominator(newConfig.vetoDenominator);
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

    function _validateVetoBounds(uint256 newThreshold) internal view {
        require(
            newThreshold * 10_000 >= members.length * MIN_VETO_BPS,
            "veto too low"
        );
    }

    function _validateVotingPower(uint256 newVotingPower) internal view {
        require(newVotingPower <= pastSupply, "voting power too high");
        require(vetoDenominator == 10_000, "denominator drift");
    }

    function _validateDenominator(uint256 newDenominator) internal pure {
        require(newDenominator == 10_000, "denominator drift");
    }
}
