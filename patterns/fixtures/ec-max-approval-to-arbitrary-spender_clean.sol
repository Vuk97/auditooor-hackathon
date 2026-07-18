// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
}

// CLEAN: exact-amount approval, whitelist enforced
contract AggregatorApprovalClean {
    IERC20 public token;
    mapping(address => bool) public trustedRouter;
    address public owner;

    constructor(address _token) { token = IERC20(_token); owner = msg.sender; }

    function addRouter(address router) external {
        require(msg.sender == owner, "not owner");
        trustedRouter[router] = true;
    }

    // CLEAN: exact-amount approval, whitelist-only routers
    function approveAndSwap(address router, uint256 amount, bytes calldata data) external {
        require(trustedRouter[router], "untrusted router"); // whitelist enforced
        token.approve(router, amount); // exact amount, not max
        (bool ok,) = router.call(data);
        require(ok, "swap failed");
        token.approve(router, 0); // reset approval after use
    }
}
