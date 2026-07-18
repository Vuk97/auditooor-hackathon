pragma solidity ^0.8.20;

interface IBeforeWithdrawHook {
    function beforeWithdraw(address user, uint256 amount) external;
}

contract StaleCheckValueUsedAfterHookCallbackPositive {
    mapping(address => uint256) public balances;
    IBeforeWithdrawHook public hook;

    constructor(IBeforeWithdrawHook hook_) {
        hook = hook_;
    }

    function seed(address user, uint256 amount) external {
        balances[user] = amount;
    }

    function withdraw(uint256 amount) external {
        uint256 cachedBalance = balances[msg.sender];
        require(cachedBalance >= amount, "insufficient");

        hook.beforeWithdraw(msg.sender, amount);

        balances[msg.sender] = cachedBalance - amount;
        payable(msg.sender).transfer(amount);
    }
}
