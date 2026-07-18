// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (a): value-moving fn guarded by `require(amt <= cap)` where `<` was
// intended (boundary_suspect=TRUE). The cap is meant to be EXCLUSIVE but the
// non-strict `<=` lets amt == cap through - a classic off-by-one cap bypass.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BoundarySuspectLeCap {
    IERC20 public token;
    uint256 public cap;
    address public treasury;

    constructor(IERC20 _t, uint256 _cap) {
        token = _t;
        cap = _cap;
    }

    // BOUNDARY-SUSPECT: non-strict <= on the tainted value `amt` vs cap. // BOUNDARY-TARGET
    function pay(uint256 amt) external {
        require(amt <= cap, "over cap");
        token.transfer(treasury, amt);
    }
}
