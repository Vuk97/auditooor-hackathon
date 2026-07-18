pragma solidity ^0.8.20;

contract EscrowClaimInternalGuardVulnerable {
    mapping(address => uint256) public escrowedRewards;
    mapping(address => uint256) public claimAvailableAt;
    mapping(address => bool) public activeClaim;
    uint256 public rewardEscrow;

    receive() external payable {}

    function fundReward() external payable {
        require(msg.value > 0, "value");
        escrowedRewards[msg.sender] += msg.value;
        rewardEscrow += msg.value;
        activeClaim[msg.sender] = true;
        claimAvailableAt[msg.sender] = block.timestamp + 14 days;
    }

    function claimAfterDelay(uint256 amount) external {
        _requireClaimReady(msg.sender);
        _claimEscrow(msg.sender, amount);
    }

    function fastClaim(uint256 amount) external {
        _claimEscrow(msg.sender, amount);
    }

    function _requireClaimReady(address account) internal view {
        require(activeClaim[account], "no claim");
        require(block.timestamp >= claimAvailableAt[account], "delay");
    }

    function _claimEscrow(address account, uint256 amount) internal {
        require(escrowedRewards[account] >= amount, "amount");
        escrowedRewards[account] -= amount;
        rewardEscrow -= amount;
        payable(account).transfer(amount);
    }
}
