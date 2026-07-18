// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (d): a caller-identity guard (require(msg.sender == owner)) - a
// comparator (==) but NOT a value-vs-cap boundary concern. boundary_suspect
// MUST be False (the == on an address is not an off-by-one cap).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BoundaryCallerIdentity {
    IERC20 public token;
    address public owner;
    address public treasury;

    constructor(IERC20 _t) {
        token = _t;
        owner = msg.sender;
    }

    // caller-identity guard - == on address, not a value-vs-cap bound.
    function pay(uint256 amt) external {
        require(msg.sender == owner, "not owner");
        token.transfer(treasury, amt);
    }
}
