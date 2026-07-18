// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeSetterVuln {
    uint256 public protocolFee;
    address public owner;

    // VULN: no upper bound — governance can set fee to 10_000 (100%).
    function setProtocolFee(uint256 newFee) external {
        require(msg.sender == owner, "not owner");
        protocolFee = newFee;
    }
}
