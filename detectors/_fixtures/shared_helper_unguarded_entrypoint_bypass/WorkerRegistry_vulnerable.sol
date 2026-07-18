pragma solidity ^0.8.20;

contract WorkerRegistryVulnerable {
    mapping(address => uint256) public stakes;
    mapping(address => bool) public deregistered;
    mapping(address => uint256) public cooldownEnds;
    uint256 public totalStake;

    receive() external payable {}

    function register() external payable {
        require(msg.value > 0, "value");
        stakes[msg.sender] += msg.value;
        totalStake += msg.value;
    }

    function deregister() external {
        require(stakes[msg.sender] > 0, "stake");
        deregistered[msg.sender] = true;
        cooldownEnds[msg.sender] = block.timestamp + 7 days;
    }

    function withdrawAfterDeregister(uint256 amount) external {
        _assertWithdrawalReady(msg.sender);
        _withdrawStake(msg.sender, amount);
    }

    function emergencyWithdraw(uint256 amount) external {
        _withdrawStake(msg.sender, amount);
    }

    function _assertWithdrawalReady(address worker) internal view {
        require(deregistered[worker], "deregister first");
        require(block.timestamp >= cooldownEnds[worker], "cooldown");
    }

    function _withdrawStake(address worker, uint256 amount) internal {
        require(stakes[worker] >= amount, "amount");
        stakes[worker] -= amount;
        totalStake -= amount;
        payable(worker).transfer(amount);
    }
}
