pragma solidity ^0.8.20;

interface IBeforeWithdrawHookClean {
    function beforeWithdraw(address user, uint256 amount) external;
}

contract StaleCheckValueUsedAfterHookCallbackClean {
    mapping(address => uint256) public balances;
    IBeforeWithdrawHookClean public hook;

    constructor(IBeforeWithdrawHookClean hook_) {
        hook = hook_;
    }

    function seed(address user, uint256 amount) external {
        balances[user] = amount;
    }

    function withdraw(uint256 amount) external {
        uint256 cachedBalance = balances[msg.sender];
        require(cachedBalance >= amount, "insufficient");

        hook.beforeWithdraw(msg.sender, amount);

        uint256 liveBalance = balances[msg.sender];
        require(liveBalance >= amount, "insufficient-after-hook");
        balances[msg.sender] = liveBalance - amount;
        payable(msg.sender).transfer(amount);
    }
}
