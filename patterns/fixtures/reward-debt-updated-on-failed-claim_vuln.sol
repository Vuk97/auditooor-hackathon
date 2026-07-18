// SPDX-License-Identifier: MIT
// Fixture: reward-debt-updated-on-failed-claim — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amt) external returns (bool);
}

contract RewardDebtFailedClaimVuln {
    struct UserInfo {
        uint256 balance;
        uint256 accountRewardDebt;
    }

    mapping(address => UserInfo) public users;
    uint256 public rewardPerShare;
    uint256 public lastReward;
    IERC20 public rewardToken;

    // VULN: try/catch swallows transfer failure; accountRewardDebt is written
    // regardless, so a failed transfer burns the user's future accrual.
    function _claimRewardToken(address user) internal {
        UserInfo storage u = users[user];
        uint256 pending = u.balance * rewardPerShare - u.accountRewardDebt;
        u.accountRewardDebt = u.balance * rewardPerShare;
        lastReward = block.timestamp;
        try rewardToken.transfer(user, pending) {
        } catch {}
    }

    // VULN: low-level .call{} with no require on success, writes rewardDebt.
    function claimReward() external {
        UserInfo storage u = users[msg.sender];
        u.accountRewardDebt = u.balance * rewardPerShare;
        (bool ok, ) = address(rewardToken).call(
            abi.encodeWithSelector(IERC20.transfer.selector, msg.sender, 1)
        );
        ok; // deliberately ignored
    }

    // VULN: raw .transfer() without require, advances rewardDebt first.
    function harvest() external {
        UserInfo storage u = users[msg.sender];
        u.accountRewardDebt = u.balance * rewardPerShare;
        rewardToken.transfer(msg.sender, 1);
    }
}
