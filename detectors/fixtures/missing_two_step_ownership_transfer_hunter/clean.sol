pragma solidity ^0.8.20;

contract TwoStepOwnerRotationClean {
    address private _owner;
    address private _pendingOwner;

    constructor() {
        _owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        _pendingOwner = newOwner;
    }

    function acceptOwnership() external {
        require(msg.sender == _pendingOwner, "not pending owner");
        _owner = _pendingOwner;
        _pendingOwner = address(0);
    }
}
