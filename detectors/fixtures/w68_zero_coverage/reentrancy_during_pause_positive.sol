// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: external hook callback fires before state update; reentrancy
// is reachable even while the contract is paused.
contract ReentrancyDuringPauseVulnerable {
    mapping(address => uint256) public balance;
    bool public paused;

    function withdrawWithHook(address hook, uint256 amount) external {
        require(balance[msg.sender] >= amount, "insufficient");
        (bool ok, ) = hook.call(abi.encodeWithSignature("onWithdraw(uint256)", amount));
        require(ok, "hook failed");
        balance[msg.sender] -= amount;
    }
}
