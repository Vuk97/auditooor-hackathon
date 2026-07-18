// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StandardFunctions {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        _;
    }

    modifier whenNotPaused() {
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function transfer(address to, uint256 amount) public nonReentrant returns (bool) {
        return true;
    }

    function viewBalance(address account) external view returns (uint256) {
        return 0;
    }

    function pureOp(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }

    function multiGuarded(address to, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        onlyOwner
        returns (bool success)
    {
        return true;
    }
}
