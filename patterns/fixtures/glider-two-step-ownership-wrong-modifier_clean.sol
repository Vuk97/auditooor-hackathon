pragma solidity ^0.8.0;

contract TwoStepClean {
    address public owner;
    address public pendingOwner;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    // Properly gated on pendingOwner, not onlyOwner
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending");
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function adminAction() external onlyOwner {
        this.acceptOwnership();
    }
}