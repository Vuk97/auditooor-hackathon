// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRewardSource {
    function claim(address user, uint256[] calldata ids) external;
    function getRewardToken() external returns (address);
}

interface IERC20x { function balanceOf(address) external view returns (uint256); }

contract SmartLoanVuln {
    address public owner;
    mapping(address => uint256) public rewards;

    // Vuln: `pair` is caller-supplied, not allow-listed; no reentrancy guard.
    function claimReward(address pair, uint256[] calldata ids) external {
        IRewardSource(pair).claim(msg.sender, ids);
        address rewardToken = IRewardSource(pair).getRewardToken();
        rewards[rewardToken] += IERC20x(rewardToken).balanceOf(address(this));
        _checkSolvent();
    }

    function _checkSolvent() internal view { /* dummy */ }
}
