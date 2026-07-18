// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAfterSwapHook {
    function afterSwap(bytes calldata data) external returns (bytes memory);
}

contract HookReturnDataLengthNotValidatedPositive {
    function trigger(IAfterSwapHook hook, bytes memory data) external returns (bytes4 selector, int256 delta) {
        return callHook(hook, data);
    }

    function callHook(IAfterSwapHook hook, bytes memory data) internal returns (bytes4 selector, int256 delta) {
        (bool ok, bytes memory result) = address(hook).call(data);
        require(ok, "hook failed");

        selector = parseSelector(result);
        delta = parseReturnDelta(result);
    }

    function parseSelector(bytes memory result) internal pure returns (bytes4 selector) {
        assembly {
            selector := mload(add(result, 0x20))
        }
    }

    function parseReturnDelta(bytes memory result) internal pure returns (int256 delta) {
        assembly {
            delta := mload(add(result, 0x40))
        }
    }
}
