// SPDX-License-Identifier: MIT
// Fixture: reward-debt-updated-on-failed-claim — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amt) external returns (bool);
}

contract RewardDebtFailedClaimClean {
    struct UserInfo {
        uint256 balance;
        uint256 accountRewardDebt;
    }

    mapping(address => UserInfo) public users;
    uint256 public rewardPerShare;
    uint256 public lastReward;
    IERC20 public rewardToken;

    // CLEAN: require(success, ...) on the transfer result before writing
    // accountRewardDebt. If the transfer fails, the debt update is reverted
    // with the rest of the tx.
    function claimReward() external {
        UserInfo storage u = users[msg.sender];
        uint256 pending = u.balance * rewardPerShare - u.accountRewardDebt;
        bool ok = rewardToken.transfer(msg.sender, pending);
        require(ok == true, "reward transfer failed");
        u.accountRewardDebt = u.balance * rewardPerShare;
        lastReward = block.timestamp;
    }

    // CLEAN: low-level call with require(success, …) guard.
    function harvest() external {
        UserInfo storage u = users[msg.sender];
        uint256 pending = u.balance * rewardPerShare - u.accountRewardDebt;
        (bool success, ) = address(rewardToken).call(
            abi.encodeWithSelector(IERC20.transfer.selector, msg.sender, pending)
        );
        require(success == true, "reward call failed");
        u.accountRewardDebt = u.balance * rewardPerShare;
    }
}
