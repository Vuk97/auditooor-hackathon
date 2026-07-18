// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract DepositVuln {
    IERC20Permit public token;

    function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        token.transferFrom(msg.sender, address(this), amount);
    }
}
