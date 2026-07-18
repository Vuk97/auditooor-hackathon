pragma solidity ^0.8.0;

contract ReturnBombClean {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    function helper(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }

    function updateValue(uint256 newValue) external {
        value = newValue;
    }
}