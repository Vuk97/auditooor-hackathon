// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FP-guard: an EIP-1967 style proxy is the delegate MACHINERY, not a trusting
// target. Its `_delegate` dispatcher is the intended caller-context primitive.
// MUST be silent.
contract ERC1967Proxy {
    address internal _implementation;

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable {
        _delegate(_implementation);
    }
}
