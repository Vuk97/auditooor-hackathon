pragma solidity ^0.8.20;

interface IInitHook {
    function beforeInitialize(bytes32 key, uint160 sqrtPriceX96, bytes calldata hookData) external;
}

contract PermissionlessInitForwardsUserBytesToHookPositive {
    IInitHook public hooks;
    mapping(bytes32 => bool) public initialized;

    constructor(IInitHook initialHooks) {
        hooks = initialHooks;
    }

    function initialize(bytes32 key, uint160 sqrtPriceX96, bytes calldata hookData) external {
        require(!initialized[key], "already initialized");
        hooks.beforeInitialize(key, sqrtPriceX96, hookData);
        initialized[key] = true;
    }
}
