pragma solidity ^0.8.20;

interface ICallbackHook {
    function beforeSwap(bytes calldata data) external returns (bytes memory);
}

contract ReturnBombClean {
    function swap(ICallbackHook hook, bytes memory data) external returns (bool ok) {
        return callHook(hook, data);
    }

    function callHook(ICallbackHook hook, bytes memory data) internal returns (bool ok) {
        assembly {
            ok := call(gas(), hook, 0, add(data, 0x20), mload(data), 0, 0)
        }
    }
}
