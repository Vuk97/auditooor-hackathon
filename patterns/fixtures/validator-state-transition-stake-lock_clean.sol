// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every user-facing stake lifecycle function branches
// on ALL non-Active validator states (Jailed, Slashed, Exited) and
// either refunds, quarantines, or reverts. The negated regex in the
// pattern requires all three words to co-occur in the body; this
// fixture ensures each function includes them, so the detector does
// NOT fire.
contract ValidatorStateTransitionStakeLockClean {
    enum ValidatorState { Active, Jailed, Slashed, Exited }

    struct ValidatorInfo {
        ValidatorState state;
        uint256 totalStake;
        uint256 rewardAcc;
    }

    mapping(bytes32 => ValidatorInfo) public validators;
    mapping(address => mapping(bytes32 => uint256)) public stakeInfo;

    function stake(bytes32 validatorId, uint256 amount) external {
        ValidatorInfo storage v = validators[validatorId];
        if (v.state == ValidatorState.Active) {
            v.totalStake += amount;
            stakeInfo[msg.sender][validatorId] += amount;
        } else if (v.state == ValidatorState.Jailed) {
            revert("validator Jailed");
        } else if (v.state == ValidatorState.Slashed) {
            revert("validator Slashed");
        } else if (v.state == ValidatorState.Exited) {
            revert("validator Exited");
        } else {
            revert("unknown state");
        }
    }

    function unstake(bytes32 validatorId, uint256 amount) external {
        ValidatorInfo storage v = validators[validatorId];
        // Explicit branches for Jailed, Slashed, Exited, Active.
        if (v.state == ValidatorState.Jailed) {
            // Quarantine: allow exit of principal, no rewards.
            stakeInfo[msg.sender][validatorId] -= amount;
        } else if (v.state == ValidatorState.Slashed) {
            // Slashed principal socialized; withdraw remainder.
            stakeInfo[msg.sender][validatorId] -= amount;
        } else if (v.state == ValidatorState.Exited) {
            stakeInfo[msg.sender][validatorId] -= amount;
            v.totalStake -= amount;
        } else {
            require(v.state == ValidatorState.Active, "unknown state");
            stakeInfo[msg.sender][validatorId] -= amount;
            v.totalStake -= amount;
        }
    }

    function claimStake(bytes32 validatorId) external {
        ValidatorInfo storage v = validators[validatorId];
        if (v.state == ValidatorState.Slashed) revert("Slashed no reward");
        if (v.state == ValidatorState.Jailed) revert("Jailed no reward");
        if (v.state == ValidatorState.Exited) revert("Exited claim via exitPath");
        require(v.state == ValidatorState.Active, "not active");
        uint256 owed = (v.rewardAcc * stakeInfo[msg.sender][validatorId]) / 1e18;
        owed;
    }
}
