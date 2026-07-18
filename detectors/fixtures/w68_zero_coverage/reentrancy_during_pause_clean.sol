// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: state updated before the external hook call (checks-effects-interactions).
contract ReentrancyDuringPauseSafe {
    mapping(address => uint256) public balance;
    bool public paused;

    function withdrawWithHook(address hook, uint256 amount) external {
        require(balance[msg.sender] >= amount, "insufficient");
        balance[msg.sender] -= amount;
        (bool ok, ) = hook.call(abi.encodeWithSignature("onWithdraw(uint256)", amount));
        require(ok, "hook failed");
    }
}
