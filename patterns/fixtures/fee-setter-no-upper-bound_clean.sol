// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeSetterClean {
    uint256 public constant MAX_FEE = 1000; // 10 %
    uint256 public protocolFee;
    address public owner;

    // CLEAN: explicit cap.
    function setProtocolFee(uint256 newFee) external {
        require(msg.sender == owner, "not owner");
        require(newFee <= MAX_FEE, "fee too high");
        protocolFee = newFee;
    }
}
