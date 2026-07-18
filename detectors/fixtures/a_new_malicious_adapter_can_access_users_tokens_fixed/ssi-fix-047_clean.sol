// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MetaSwapAdapterApprovalClean {
    mapping(address => address) internal approvedSpender;
    address public lastAdapter;

    function configureSpender(address user, address adapter) external {
        approvedSpender[user] = adapter;
    }

    function _validateAdapter(address user) internal view returns (address) {
        address spender = approvedSpender[user];
        require(spender != address(0), "spender missing");
        return spender;
    }

    function approveAdapter(address user, address token, uint256 amount) external returns (bool) {
        address spender = _validateAdapter(user);
        lastAdapter = spender;
        (bool ok,) = token.call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", user, spender, amount)
        );
        return ok;
    }
}
