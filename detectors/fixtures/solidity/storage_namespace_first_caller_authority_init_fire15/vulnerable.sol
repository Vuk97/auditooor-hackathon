// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library AccountNamespace {
    // erc7201:auditooor.fire15.account
    bytes32 internal constant ACCOUNT_STORAGE_SLOT =
        keccak256("auditooor.fire15.account.storage");

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

contract NamespaceWalletModule {
    error AlreadyInitialized();

    function initializeNamespace(address authority_, address guardian_) external {
        AccountNamespace.Layout storage l = AccountNamespace.layout();
        if (l.initialized) revert AlreadyInitialized();

        l.authority = authority_;
        l.guardian = guardian_;
        l.initialized = true;
    }
}
