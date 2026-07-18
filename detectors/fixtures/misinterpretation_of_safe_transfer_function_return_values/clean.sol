// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

library SafeTransferRevertShim {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount)
        );
        require(success, "low-level transfer failed");
        if (data.length > 0) {
            require(abi.decode(data, (bool)), "erc20 transfer returned false");
        }
    }
}

contract MisinterpretationOfSafeTransferFunctionReturnValuesClean {
    using SafeTransferRevertShim for IERC20;

    mapping(address => uint256) public released;

    function sweep(address token, address to, uint256 amount) external {
        IERC20(token).safeTransfer(to, amount);
        released[to] += amount;
    }
}
