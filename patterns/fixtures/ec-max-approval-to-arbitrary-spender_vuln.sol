// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

// VULN: max approval granted to user-supplied address without whitelist check
// Loss ref: Multichain/AnySwap ~$3M Jan 2022; Socket Gateway ~$3.3M Jan 2024
// https://rekt.news/anyswap-multichain-rekt/
// https://rekt.news/socket-rekt/
contract AggregatorApprovalVuln {
    IERC20 public token;

    constructor(address _token) { token = IERC20(_token); }

    // VULN: router is user-supplied, gets type(uint256).max approval — no whitelist
    function approveAndSwap(address router, uint256 amount, bytes calldata data) external {
        token.approve(router, type(uint256).max); // infinite to arbitrary address
        (bool ok,) = router.call(data); // call arbitrary router
        require(ok, "swap failed");
    }
}
