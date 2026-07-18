// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// CLEAN: no ecrecover call anywhere. Neither sub-rule fires.
// Verifies the first gating condition: ecrecover must be genuinely present.
contract SigReplayNoEcrecover {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
