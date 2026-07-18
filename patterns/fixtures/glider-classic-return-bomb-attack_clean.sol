// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RouterClean {
    address public owner;
    uint256 public counter;

    function forward(address target, bytes calldata data) external returns (bytes memory) {
        assembly {
            let ptr := mload(0x40)
            let size := returndatasize()
            if gt(size, 0x1000) {
                revert(0, 0)
            }
            returndatacopy(ptr, 0, size)
            mstore(0x40, add(ptr, size))
            return(ptr, size)
        }
    }

    function processResult(bytes memory ret) external pure returns (uint256) {
        uint256 result = abi.decode(ret, (uint256));
        return result;
    }

    function helper(address target, bytes calldata data) external {
        this.forward(target, data);
    }
}