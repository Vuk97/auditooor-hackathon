pragma solidity ^0.8.20;

interface ICallbackHook {
    function beforeSwap(bytes calldata data) external returns (bytes memory);
}

contract ReturnBombPositive {
    function swap(ICallbackHook hook, bytes memory data) external returns (bool, bytes memory) {
        return callHook(hook, data);
    }

    function callHook(ICallbackHook hook, bytes memory data) internal returns (bool ok, bytes memory result) {
        address target = address(hook);
        (bool hookOk, bytes memory hookResult) = target.call(data);
        return (hookOk, hookResult);
    }
}
