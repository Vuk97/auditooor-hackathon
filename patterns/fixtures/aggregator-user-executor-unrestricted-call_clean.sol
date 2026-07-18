// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract AggregatorRouterClean {
    struct SwapParams {
        address srcToken;
        address dstToken;
        uint256 amount;
        address executor;
        bytes executeParams;
    }

    mapping(address => bool) public allowedExecutor;

    function swap(SwapParams calldata p) external returns (uint256) {
        // CLEAN: executor whitelist
        require(allowedExecutor[p.executor], "executor not allowed");
        if (p.amount > 0) {
            IERC20(p.srcToken).transferFrom(msg.sender, address(this), p.amount);
        }
        (bool ok, ) = p.executor.call(p.executeParams);
        require(ok, "exec failed");
        return IERC20(p.dstToken).balanceOf(msg.sender);
    }
}
