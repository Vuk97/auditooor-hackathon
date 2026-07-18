// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// BACKWARD-ENTRYPOINT GUARD fixture (D-connect backward pass / P0).
//
// The FORWARD closure correction sees a guard only in the slice source/sink's
// OWN forward closure. When the slice SOURCE is an INTERNAL value-mover, its
// caller-side guard (a modifier on the public entrypoint) lives UP the call
// graph and is INVISIBLE to the forward pass -> the path stays unguarded=true
// (the documented under-flip). This recurs for every internal value-mover that
// is access-controlled at its entrypoint(s) - real anchor: polygon
// StakeManager._delegationDeposit, an `internal` transferFrom mover whose only
// entrypoints delegationDeposit/delegationDepositPOL are `external onlyDelegation`.
//
// Two internal value-movers model the two outcomes:
//   - `_moveGuarded`:   reached ONLY by pull/pullAlt, BOTH external onlyOwner
//                       -> backward pass flips it to unguarded=false
//                       (guarded-via-all-entrypoints).
//   - `_moveMixed`:     reached by pullMixed (onlyOwner) AND pullOpen
//                       (permissionless) -> ONE unguarded entrypoint exists
//                       -> backward pass KEEPS unguarded=true (never over-flip).
contract BackwardEntrypointGuard {
    IERC20 public token;
    address public treasury;
    address public owner;

    constructor(IERC20 _token, address _treasury) {
        token = _token;
        treasury = _treasury;
        owner = msg.sender;
    }

    // The guard lives HERE, on the entrypoint - NOT in the internal mover.
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ---- internal value-mover #1: ALL entrypoints guarded -------------------
    function _moveGuarded(uint256 amount) internal {
        token.transferFrom(treasury, msg.sender, amount);
    }

    function pull(uint256 amount) external onlyOwner {
        _moveGuarded(amount);
    }

    function pullAlt(uint256 amount) external onlyOwner {
        _moveGuarded(amount);
    }

    // ---- internal value-mover #2: ONE entrypoint UNGUARDED ------------------
    function _moveMixed(uint256 amount) internal {
        token.transferFrom(treasury, msg.sender, amount);
    }

    function pullMixed(uint256 amount) external onlyOwner {
        _moveMixed(amount);
    }

    // PERMISSIONLESS entrypoint: makes _moveMixed genuinely reachable unguarded.
    function pullOpen(uint256 amount) external {
        _moveMixed(amount);
    }
}
