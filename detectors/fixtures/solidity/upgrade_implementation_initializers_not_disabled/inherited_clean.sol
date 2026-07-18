pragma solidity ^0.8.20;

contract Initializable {
    modifier initializer() {
        _;
    }

    function _disableInitializers() internal {}
}

contract LockedBase is Initializable {
    constructor() {
        _disableInitializers();
    }
}

contract VaultUpgradeable is LockedBase {
    address public owner;

    function initialize(address initialOwner) external initializer {
        owner = initialOwner;
    }
}
