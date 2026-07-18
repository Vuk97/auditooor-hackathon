// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// VULNERABLE: an attacker-controlled `amount` parameter flows
//   withdraw(amount) -> _route(amount) -> _pay(amount) -> token.transferFrom(.., amount)
// crossing >=2 internal call hops, with NO require/assert bounding `amount`
// dominating the slice. The recovered DefUsePath must be unguarded:true.
contract Vulnerable {
    IERC20 public token;
    address public treasury;

    constructor(IERC20 _token, address _treasury) {
        token = _token;
        treasury = _treasury;
    }

    // entrypoint: attacker chooses amount
    function withdraw(uint256 amount) external {
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
