// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function safeApprove(address, uint256) external;
    function forceApprove(address, uint256) external;
}

contract ApproveClean {
    IERC20 public token;
    mapping(address => bool) public approvedRouters;

    modifier onlyOwner() {
        require(msg.sender == address(0x1), "not owner");
        _;
    }

    function addRouter(address router) external onlyOwner {
        approvedRouters[router] = true;
    }

    function swapVia(address router, bytes calldata data) external returns (bool ok) {
        require(approvedRouters[router], "router not approved");
        token.safeApprove(router, type(uint256).max);
        (ok, ) = router.call(data);
    }
}