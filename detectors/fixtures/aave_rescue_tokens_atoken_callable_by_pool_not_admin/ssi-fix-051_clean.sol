// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransfer(address to, uint256 amount) external;
}

contract PoolAdminRescueAToken {
    address public immutable POOL;
    address public immutable POOL_ADMIN;

    constructor(address pool, address poolAdmin) {
        POOL = pool;
        POOL_ADMIN = poolAdmin;
    }

    modifier onlyPoolAdmin() {
        require(msg.sender == POOL_ADMIN, "ONLY_POOL_ADMIN");
        _;
    }

    function rescueTokens(address token, address to, uint256 amount) external onlyPoolAdmin {
        IERC20Like(token).safeTransfer(to, amount);
    }
}
