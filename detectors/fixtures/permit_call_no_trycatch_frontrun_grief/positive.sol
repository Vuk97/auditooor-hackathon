// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: a generic vault forwards a user-supplied EIP-2612 permit signature to
// token.permit() bare (unwrapped) and with NO allowance() pre-check.
// A front-runner can replay the signed permit first, consuming the one-shot
// nonce; this combined tx then reverts (grief DoS).

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VaultPermitVuln {
    IERC20Permit public token;
    mapping(address => uint256) public deposits;

    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // VULN: bare permit forward, no try/catch, no allowance pre-check.
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }
}
