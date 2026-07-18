// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A transparent proxy with proper admin/impl selector-space SEPARATION via an
// ifAdmin router (OZ pattern): admin selectors are handled at the proxy, all
// other selectors are forwarded to the impl. GEN-EL2 must stay SILENT
// (safe form b).
contract BenignProxy {
    address internal implementation;
    address internal admin;

    modifier ifAdmin() {
        if (msg.sender == admin) {
            _;
        } else {
            _delegate(implementation);
        }
    }

    function upgradeTo(address newImpl) external ifAdmin {
        implementation = newImpl;
    }

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable ifAdmin {
        _delegate(implementation);
    }
}
