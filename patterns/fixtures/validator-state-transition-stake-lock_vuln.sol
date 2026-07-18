// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal validator-staking contract with the C0377 bug shape: the
// stake/unstake path inspects validator lifecycle state but only
// branches on Active vs Exited. Transitions into Jailed or Slashed
// are silently dropped — pending stakes land in the wrong accounting
// bucket and either lock or get credited to prior stakers.
contract ValidatorStateTransitionStakeLockVuln {
    enum ValidatorState { Active, Jailed, Slashed, Exited }

    struct ValidatorInfo {
        ValidatorState state;
        uint256 totalStake;
        uint256 rewardAcc;
    }

    mapping(bytes32 => ValidatorInfo) public validators;
    mapping(address => mapping(bytes32 => uint256)) public stakeInfo;

    // VULN: reads validatorState, only handles Active explicitly,
    // falls through for Jailed / Slashed (un-credited). Exited check
    // is a revert but Jailed and Slashed are NOT branched on.
    function stake(bytes32 validatorId, uint256 amount) external {
        ValidatorInfo storage v = validators[validatorId];
        if (v.state == ValidatorState.Active) {
            v.totalStake += amount;
            stakeInfo[msg.sender][validatorId] += amount;
        }
        // FALL-THROUGH: Jailed / Slashed paths do nothing; the caller's
        // amount is not recorded but tokens would have been transferred
        // in a real contract, locking them.
    }

    // VULN: unstake only checks Active and Exited. Jailed / Slashed
    // stakes can never exit.
    function unstake(bytes32 validatorId, uint256 amount) external {
        ValidatorInfo storage v = validators[validatorId];
        require(v.state == ValidatorState.Active, "not active");
        stakeInfo[msg.sender][validatorId] -= amount;
        v.totalStake -= amount;
    }

    // VULN: claim rewards reads validator.state but only handles a single
    // transition. This is the "old stakers can steal deposits of new
    // stakers" surface in StakingFundsVault.
    function claimStake(bytes32 validatorId) external {
        ValidatorInfo storage v = validators[validatorId];
        require(v.state == ValidatorState.Active, "not active");
        uint256 owed = (v.rewardAcc * stakeInfo[msg.sender][validatorId]) / 1e18;
        owed;
    }

    function _unstake(bytes32 validatorId, uint256 amount) internal {
        ValidatorInfo storage v = validators[validatorId];
        if (v.state == ValidatorState.Active) {
            v.totalStake -= amount;
        }
    }
}
