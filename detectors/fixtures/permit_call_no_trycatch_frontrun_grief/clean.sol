// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: the permit call is wrapped in try/catch AND gated behind an
// allowance() pre-check, so a front-run nonce-consumption is swallowed and the
// transferFrom still enforces the (already-granted) allowance. No grief race.

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
    function allowance(address owner, address spender) external view returns (uint256);
}

contract VaultPermitClean {
    IERC20Permit public token;
    mapping(address => uint256) public deposits;

    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // CLEAN: skip permit if already approved; wrap in try/catch otherwise.
        if (token.allowance(msg.sender, address(this)) < amount) {
            try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
        }
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }
}
