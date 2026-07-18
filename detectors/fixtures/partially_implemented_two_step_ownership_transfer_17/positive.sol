pragma solidity ^0.8.20;

contract PartialTwoStepOwnershipTransferPositive {
    address public owner;
    address public pendingOwner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        pendingOwner = newOwner;
    }

    function acceptOwnership() external onlyOwner {
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
