// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20Permit2 {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract DepositClean {
    IERC20Permit2 public token;

    function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (token.allowance(msg.sender, address(this)) < amount) {
            try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
        }
        token.transferFrom(msg.sender, address(this), amount);
    }
}
