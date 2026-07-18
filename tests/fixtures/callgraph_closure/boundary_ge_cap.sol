// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (b-variant): the `>=` non-strict mirror. `require(remaining >= amt)`
// vs a strict `>` is the symmetric off-by-one shape on the `>=` side. Here the
// VALUE side is `amt` compared against a bound `remaining` (a state/limit-like
// name) - boundary_suspect=TRUE on the `>=` op too.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BoundaryGeCap {
    IERC20 public token;
    uint256 public maxLimit;
    address public treasury;

    constructor(IERC20 _t, uint256 _max) {
        token = _t;
        maxLimit = _max;
    }

    // BOUNDARY-SUSPECT: non-strict >= comparing the cap `maxLimit` against value `amt`.
    function pay(uint256 amt) external {
        require(maxLimit >= amt, "over limit");
        token.transfer(treasury, amt);
    }
}
