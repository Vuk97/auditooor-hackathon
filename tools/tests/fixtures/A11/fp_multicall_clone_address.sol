// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FP-guard batch: self-delegatecall Multicall, OZ Address.functionDelegateCall,
// and Clones.clone deployment. All are intended-caller-context primitives and
// MUST be silent.

contract Multicall {
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "call failed");
            results[i] = ret;
        }
    }
}

library Address {
    function functionDelegateCall(address target, bytes memory data)
        internal
        returns (bytes memory)
    {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return returndata;
    }
}

library Clones {
    function clone(address implementation) internal returns (address instance) {
        assembly {
            let ptr := mload(0x40)
            instance := create(0, ptr, 0x37)
        }
        require(instance != address(0), "clone failed");
    }
}
