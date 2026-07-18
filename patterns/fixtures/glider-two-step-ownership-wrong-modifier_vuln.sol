pragma solidity ^0.8.0;

contract TwoStepVuln {
    address public owner;
    address public pendingOwner;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    function acceptOwnership() external onlyOwner {
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function somePublicFunction() external {
        // This exists so acceptOwnership is not a leaf helper.
        // It is called by nobody in this contract, making it a leaf,
        // but we need acceptOwnership to NOT be a leaf helper.
        // Actually we need acceptOwnership to be called by someone.
    }

    function adminAction() external onlyOwner {
        // This function calls acceptOwnership internally, so acceptOwnership
        // is not a leaf helper (it has an internal caller).
        this.acceptOwnership();
    }
}