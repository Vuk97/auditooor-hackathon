// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Case 2 (consumer re-checks -> 0).
// BENIGN control: even with a bypass entry, the consumer sink RE-CHECKS the
// caller identity (has_guard_in_closure(consumer) == True), so module A does
// NOT blindly trust B - condition (b) fails and NO seam is emitted.
contract Auth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function _requireOwner() internal view {
        require(msg.sender == owner, "not owner");
    }
}

contract Vault is Auth {
    uint256 public fee; // W

    // GUARDED producer of W.
    function setFee(uint256 newFee) external {
        _requireOwner();
        fee = newFee;
    }

    // Consumer sink of W that RE-CHECKS the caller identity itself -> benign.
    function readFee() external view returns (uint256) {
        _requireOwner();
        return fee;
    }
}
