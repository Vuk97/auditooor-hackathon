// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every privileged function carries the onlyOwner modifier.
contract ArGoProtocolClean {
    address public owner;
    mapping(address => bool) public operators;
    uint256 public fee;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        (bool success, ) = token.call(
            abi.encodeWithSelector(0xa9059cbb, msg.sender, amount)
        );
        require(success, "transfer failed");
    }

    function addOperator(address op) external onlyOwner {
        operators[op] = true;
    }

    function removeOperator(address op) external onlyOwner {
        operators[op] = false;
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }

    function getFee() external view returns (uint256) {
        return fee;
    }
}
