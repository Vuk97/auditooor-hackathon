// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// B-hops cycle-termination fixture: a MUTUALLY-RECURSIVE pair (ping <-> pong)
// sits on the path from the attacker source to the value-moving sink. With an
// UNBOUNDED hop ceiling, only the visited-(fn,var) set prevents an infinite walk.
// The slicer MUST terminate (not hang / not OOM) and still recover the source.
//   withdraw(amount) -> ping(amount) <-> pong(amount) -> _pay -> transferFrom
contract RecursiveCycle {
    IERC20 public token;
    address public treasury;
    uint256 public n;

    constructor(IERC20 _token, address _treasury) {
        token = _token;
        treasury = _treasury;
    }

    function withdraw(uint256 amount) external {
        ping(amount);
    }

    // mutually-recursive cycle: ping calls pong, pong calls ping.
    function ping(uint256 a) internal {
        if (n > 0) {
            n -= 1;
            pong(a);
        } else {
            _pay(a);
        }
    }

    function pong(uint256 b) internal {
        ping(b);
    }

    function _pay(uint256 amount) internal {
        token.transferFrom(treasury, msg.sender, amount);
    }
}
