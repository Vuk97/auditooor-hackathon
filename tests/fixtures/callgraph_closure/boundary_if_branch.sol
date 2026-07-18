// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture: an explicit `if`-statement guard (lowered to a CFG IF node with
// son_true / son_false) so the branch-target navigator has a real branch to
// read. `if (amt <= cap) { transfer } else { revert }` - the non-strict <= is
// still boundary-suspect, AND the EFFECT runs in the son_true (condition holds)
// arm, which is the CORRECT orientation here.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BoundaryIfBranch {
    IERC20 public token;
    uint256 public cap;
    address public treasury;

    constructor(IERC20 _t, uint256 _cap) {
        token = _t;
        cap = _cap;
    }

    function pay(uint256 amt) external {
        if (amt <= cap) {
            token.transfer(treasury, amt);
        } else {
            revert("over cap");
        }
    }
}
