pragma solidity ^0.8.20;

contract CooldownMismatchPositive {
    uint256 public cooldownEnd;
    uint256 public cooldownDuration = 3 days;

    function startCooldown() external {
        cooldownEnd = block.timestamp + cooldownDuration;
    }

    function unstake() external view returns (bool) {
        uint256 currentTime = block.timestamp * 1000;
        require(currentTime >= cooldownEnd, "cooldown active");
        return true;
    }
}
