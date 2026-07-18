// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// B-hops unbounded fixture: an attacker-controlled `amount` flows through TEN
// internal call hops before reaching the value-moving sink:
//   withdraw(amount) -> h1 -> h2 -> h3 -> h4 -> h5 -> h6 -> h7 -> h8 -> h9
//   -> _pay -> token.transferFrom(.., amount)
// with NO require/assert dominating the slice. Under the OLD MAX_HOPS_DEFAULT=6
// the recovered source would be "param-depth-bound" (truncated). Under the
// unbounded ceiling the slice reaches the real "param-entrypoint" source at
// withdraw() with NO dataflow_truncated flag. The visited-(fn,var) set is the
// terminator; the HIGH ceiling is never hit by 10 hops.
contract DeepChain {
    IERC20 public token;
    address public treasury;

    constructor(IERC20 _token, address _treasury) {
        token = _token;
        treasury = _treasury;
    }

    // entrypoint: attacker chooses amount (the real source)
    function withdraw(uint256 amount) external {
        h1(amount);
    }

    function h1(uint256 a1) internal { h2(a1); }
    function h2(uint256 a2) internal { h3(a2); }
    function h3(uint256 a3) internal { h4(a3); }
    function h4(uint256 a4) internal { h5(a4); }
    function h5(uint256 a5) internal { h6(a5); }
    function h6(uint256 a6) internal { h7(a6); }
    function h7(uint256 a7) internal { h8(a7); }
    function h8(uint256 a8) internal { h9(a8); }
    function h9(uint256 a9) internal { _pay(a9); }

    // value-moving sink
    function _pay(uint256 amount) internal {
        token.transferFrom(treasury, msg.sender, amount);
    }
}
