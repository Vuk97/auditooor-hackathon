pragma solidity ^0.8.20;

interface IInitHook {
    function beforeInitialize(bytes32 key, uint160 sqrtPriceX96, bytes calldata hookData) external;
}

contract PermissionlessInitForwardsUserBytesToHookClean {
    IInitHook public hooks;
    address public owner;
    mapping(bytes32 => bool) public initialized;

    constructor(IInitHook initialHooks) {
        hooks = initialHooks;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function initialize(bytes32 key, uint160 sqrtPriceX96, bytes calldata hookData) external onlyOwner {
        require(!initialized[key], "already initialized");
        bytes memory fixedConfig = abi.encode(owner, key, sqrtPriceX96);
        hooks.beforeInitialize(key, sqrtPriceX96, fixedConfig);
        initialized[key] = true;
        hookData;
    }
}
