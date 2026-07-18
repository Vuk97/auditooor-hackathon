// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A proxy whose fallback() delegatecalls the implementation for ANY selector,
// while ALSO exposing admin fns at the proxy level with NO admin/impl
// selector-space separation (no ifAdmin router). GEN-EL2 must FIRE
// (proxy-fallback-clash, no-admin-impl-separation): an impl fn whose 4-byte
// selector equals `upgradeTo`/`changeAdmin` is shadowed/unreachable.
contract FireProxy {
    address internal implementation;
    address internal admin;

    function upgradeTo(address newImpl) external {
        require(msg.sender == admin, "not admin");
        implementation = newImpl;
    }

    function changeAdmin(address newAdmin) external {
        require(msg.sender == admin, "not admin");
        admin = newAdmin;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
