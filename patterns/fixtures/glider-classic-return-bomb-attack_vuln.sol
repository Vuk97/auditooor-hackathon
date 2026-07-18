// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RouterVuln {
    address public owner;
    uint256 public counter;

    function forward(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory ret) = target.delegatecall(data);
        require(success, "fail");
        return ret;
    }

    function processResult(bytes memory ret) external pure returns (uint256) {
        uint256 result = abi.decode(ret, (uint256));
        return result;
    }

    function helper(address target, bytes calldata data) external {
        this.forward(target, data);
    }
}