// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function safeApprove(address, uint256) external;
    function forceApprove(address, uint256) external;
}

contract ApproveVuln {
    IERC20 public token;

    function swapVia(address router, bytes calldata data) external returns (bool ok) {
        token.safeApprove(router, type(uint256).max);
        (ok, ) = router.call(data);
    }
}