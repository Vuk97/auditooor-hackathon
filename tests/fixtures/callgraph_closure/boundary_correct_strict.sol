// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (c): the CORRECT strict-bound form `require(amt < cap)`. The strict
// comparator is the right guard, so boundary_suspect MUST be False
// (never-false-positive on a correct strict cap).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BoundaryCorrectStrict {
    IERC20 public token;
    uint256 public cap;
    address public treasury;

    constructor(IERC20 _t, uint256 _cap) {
        token = _t;
        cap = _cap;
    }

    // CORRECT: strict `<` on the tainted value `amt` vs cap -> NOT boundary-suspect.
    function pay(uint256 amt) external {
        require(amt < cap, "at/over cap");
        token.transfer(treasury, amt);
    }
}
