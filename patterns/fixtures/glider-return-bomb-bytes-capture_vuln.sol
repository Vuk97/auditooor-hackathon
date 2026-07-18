pragma solidity ^0.8.0;

contract ReturnBombVuln {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        ret;
    }

    function helper(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }

    function updateValue(uint256 newValue) external {
        value = newValue;
    }
}