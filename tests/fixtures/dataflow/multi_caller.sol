// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// MULTI-CALLER fan-out fixture.
//   The value-moving sink token.transferFrom(.., a) sits in _pay(a).
//   _pay is reached from TWO distinct caller chains, BOTH >= 2 hops deep:
//     chain A: withdrawA(amount) -> _routeA(amt) -> _pay(a)
//     chain B: withdrawB(qty)    -> _routeB(amt) -> _pay(a)
//   A correct fan-out backward slice must recover BOTH chains (>=2 distinct
//   caller frames feeding the same param), each at call_depth >= 2.
//   The first-caller-only walk recovers ONLY one chain - that is the
//   mutation-pair witness for the fan-out logic.
contract MultiCaller {
    IERC20 public token;
    address public treasury;

    constructor(IERC20 _token, address _treasury) {
        token = _token;
        treasury = _treasury;
    }

    // entrypoint A
    function withdrawA(uint256 amount) external {
        _routeA(amount);
    }

    // entrypoint B (distinct top-level param name)
    function withdrawB(uint256 qty) external {
        _routeB(qty);
    }

    // hop A.1
    function _routeA(uint256 amt) internal {
        _pay(amt);
    }

    // hop B.1
    function _routeB(uint256 amt) internal {
        _pay(amt);
    }

    // shared hop 2 -> external value-moving sink
    function _pay(uint256 a) internal {
        token.transferFrom(treasury, msg.sender, a);
    }
}
