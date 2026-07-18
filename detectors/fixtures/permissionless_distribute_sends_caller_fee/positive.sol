pragma solidity ^0.8.20;

contract PermissionlessDistributeSendsCallerFeePositive {
    mapping(uint256 => uint256) public pendingRewards;
    uint256 public royaltyFees;

    receive() external payable {}

    function depositRewards(uint256 credId) external payable {
        pendingRewards[credId] += msg.value;
        royaltyFees += msg.value / 10;
    }

    function distribute(uint256 credId) external {
        uint256 reward = pendingRewards[credId];
        uint256 royaltyFee = reward / 20;

        pendingRewards[credId] = 0;
        royaltyFees -= royaltyFee;
        payable(msg.sender).transfer(royaltyFee);
    }
}
