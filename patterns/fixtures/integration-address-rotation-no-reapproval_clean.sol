// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: integration rotation revokes old allowance and grants new.

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function forceApprove(IERC20 tok, address sp, uint256 amt) internal {
        tok.approve(sp, 0);
        tok.approve(sp, amt);
    }
}

contract CleanVault {
    using SafeERC20 for IERC20;

    address public owner;
    address public aavePool;
    address public router;
    IERC20 public immutable token;

    constructor(address _owner, address _token) {
        owner = _owner;
        token = IERC20(_token);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "!owner");
        _;
    }

    // CLEAN: revoke old, assign new, grant new.
    function setAavePool(address newPool) external onlyOwner {
        address old = aavePool;
        if (old != address(0)) {
            token.approve(old, 0);
        }
        aavePool = newPool;
        if (newPool != address(0)) {
            token.forceApprove(newPool, type(uint256).max);
        }
    }

    function setRouter(address newRouter) external onlyOwner {
        address old = router;
        if (old != address(0)) token.approve(old, 0);
        router = newRouter;
        if (newRouter != address(0)) token.forceApprove(newRouter, type(uint256).max);
    }
}
