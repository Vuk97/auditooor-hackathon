// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MetaSwapAdapterApprovalPositive {
    mapping(address => address) internal approvedSpender;
    address public lastAdapter;

    function configureSpender(address user, address adapter) external {
        approvedSpender[user] = adapter;
    }

    function approveAdapter(address user, address token, uint256 amount) external returns (bool) {
        address spender = approvedSpender[user];
        lastAdapter = spender;
        (bool ok,) = token.call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", user, spender, amount)
        );
        return ok;
    }
}
