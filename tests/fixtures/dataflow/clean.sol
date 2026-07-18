// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// CLEAN: same multi-hop flow as vulnerable.sol, BUT a require(amt <= cap)
//   dominates the slice before `amt` reaches the transferFrom sink.
//   withdraw(amount) -> _route(amount) [require(amt<=cap)] -> _pay(amount) -> transferFrom
// The recovered DefUsePath must be unguarded:false with a populated guard_nodes.
contract Clean {
    IERC20 public token;
    address public treasury;
    uint256 public cap;

    constructor(IERC20 _token, address _treasury, uint256 _cap) {
        token = _token;
        treasury = _treasury;
        cap = _cap;
    }

    // entrypoint: attacker chooses amount
    function withdraw(uint256 amount) external {
        _route(amount);
    }

    // hop 1 - guard dominates the tainted slice here
    function _route(uint256 amt) internal {
        require(amt <= cap, "over cap");
        _pay(amt);
    }

    // hop 2 -> external value-moving sink
    function _pay(uint256 a) internal {
        token.transferFrom(treasury, msg.sender, a);
    }
}
