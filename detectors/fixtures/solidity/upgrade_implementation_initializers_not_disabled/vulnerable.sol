pragma solidity ^0.8.20;

contract Initializable {
    modifier initializer() {
        _;
    }
}

contract VaultUpgradeable is Initializable {
    address public owner;

    function initialize(address initialOwner) external initializer {
        owner = initialOwner;
    }
}
