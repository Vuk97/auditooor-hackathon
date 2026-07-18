// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OptionsPoolVuln {
    mapping(address => uint256) public shares;
    mapping(address => uint256) public mintedOptions;
    uint256 public totalShares;

    function _rewardBalance() internal view returns (uint256) {
        return address(this).balance;
    }

    // VULN: reward based on caller's FULL share, regardless of how much
    // they are unminting. Partial exits drain the reward pool.
    function unmintWithRewards(uint256 amountOfOptions) external {
        require(mintedOptions[msg.sender] >= amountOfOptions, "exceeds");
        uint256 rewardsToSend = (shares[msg.sender] * _rewardBalance()) / totalShares;
        mintedOptions[msg.sender] -= amountOfOptions;
        (bool ok, ) = msg.sender.call{value: rewardsToSend}("");
        require(ok, "send");
    }

    receive() external payable {}
}
