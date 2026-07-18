// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library AccountNamespaceClean {
    // erc7201:auditooor.fire15.account.clean
    bytes32 internal constant ACCOUNT_STORAGE_SLOT =
        keccak256("auditooor.fire15.account.clean.storage");

    struct Layout {
        bool initialized;
        address authority;
        address guardian;
    }

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = ACCOUNT_STORAGE_SLOT;
        assembly {
            l.slot := slot
        }
    }
}

contract NamespaceWalletModuleClean {
    error AlreadyInitialized();

    address public immutable factory;

    constructor(address factory_) {
        factory = factory_;
    }

    function initializeNamespace(address authority_, address guardian_) external {
        require(msg.sender == factory, "factory only");

        AccountNamespaceClean.Layout storage l = AccountNamespaceClean.layout();
        if (l.initialized) revert AlreadyInitialized();

        l.authority = authority_;
        l.guardian = guardian_;
        l.initialized = true;
    }
}
