// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: emergencyWithdraw, addOperator, removeOperator, pause, and setFee
// are all privileged functions declared external but missing the onlyOwner
// modifier. The contract DOES define and use onlyOwner elsewhere (setOwner),
// so the omission is a clear access-control gap.
contract ArGoProtocolVuln {
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

    // CLEAN: properly protected
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // VULN: missing onlyOwner — anyone can drain funds
    function emergencyWithdraw(address token, uint256 amount) external {
        (bool success, ) = token.call(
            abi.encodeWithSelector(0xa9059cbb, msg.sender, amount)
        );
        require(success, "transfer failed");
    }

    // VULN: missing onlyOwner
    function addOperator(address op) external {
        operators[op] = true;
    }

    // VULN: missing onlyOwner
    function removeOperator(address op) external {
        operators[op] = false;
    }

    // VULN: missing onlyOwner
    function pause() external {
        paused = true;
    }

    // VULN: missing onlyOwner
    function unpause() external {
        paused = false;
    }

    // VULN: missing onlyOwner
    function setFee(uint256 newFee) external {
        fee = newFee;
    }

    // Harmless getter — should NOT be flagged (pure/view)
    function getFee() external view returns (uint256) {
        return fee;
    }
}
