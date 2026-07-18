pragma solidity ^0.8.20;

contract Initializable {
    modifier initializer() {
        _;
    }
}

abstract contract BaseUpgradeable is Initializable {
    address public owner;

    function initialize(address initialOwner) external initializer {
        owner = initialOwner;
    }
}
