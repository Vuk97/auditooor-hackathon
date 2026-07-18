// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OptionsPoolClean {
    mapping(address => uint256) public shares;
    mapping(address => uint256) public mintedOptions;
    uint256 public totalShares;

    function _rewardBalance() internal view returns (uint256) {
        return address(this).balance;
    }

    // FIXED: scale by the fraction being exited (amountOfOptions / mintedOptions[user]).
    function unmintWithRewards(uint256 amountOfOptions) external {
        uint256 minted = mintedOptions[msg.sender];
        require(minted >= amountOfOptions && amountOfOptions > 0, "exceeds");
        uint256 scaledShares = (shares[msg.sender] * amountOfOptions) / minted;
        uint256 rewardsToSend = (scaledShares * _rewardBalance()) / totalShares;
        shares[msg.sender] -= scaledShares;
        totalShares -= scaledShares;
        mintedOptions[msg.sender] -= amountOfOptions;
        (bool ok, ) = msg.sender.call{value: rewardsToSend}("");
        require(ok, "send");
    }

    receive() external payable {}
}
