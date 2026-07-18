// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// UP-GRAPH GUARD fixture (D-connect / P0 keystone).
//
// An attacker-shaped `amount` flows:
//   withdraw(amount) -> _route(amount) -> _pay(amount) -> token.transferFrom(.., amount)
// crossing >=2 internal hops, with NO require bounding `amount` ON the slice.
//
// BUT the entrypoint `withdraw` carries an `onlyOwner` modifier whose BODY is a
// real caller-identity guard `require(msg.sender == owner)`. That guard sits UP
// the call graph (in a DIFFERENT unit - the modifier body), and it does NOT name
// the tracked `amount` var, so the SLICE-LOCAL `unguarded` computation MISSES it
// and (wrongly) reports unguarded=true. Only the inter-procedural CLOSURE
// (has_guard_in_closure, which folds modifier bodies) sees the guard and flips
// unguarded -> false.
//
// This is the SSV-class over-report: a role-gated path looks unguarded slice-
// locally but is actually access-controlled.
contract UpGraphGuard {
    IERC20 public token;
    address public treasury;
    address public owner;

    constructor(IERC20 _token, address _treasury) {
        token = _token;
        treasury = _treasury;
        owner = msg.sender;
    }

    // The guard lives HERE, in the modifier body - a different unit from the slice.
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // entrypoint: role-gated by onlyOwner (the up-graph guard)
    function withdraw(uint256 amount) external onlyOwner {
        _route(amount);
    }

    // hop 1
    function _route(uint256 amt) internal {
        _pay(amt);
    }

    // hop 2 -> external value-moving sink
    function _pay(uint256 a) internal {
        token.transferFrom(treasury, msg.sender, a);
    }
}
