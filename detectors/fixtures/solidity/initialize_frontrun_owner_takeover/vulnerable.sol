pragma solidity ^0.8.20;

contract Initializable {
    modifier initializer() {
        _;
    }
}

contract Wallet is Initializable {
    address public owner;
    address public controller;

    function initialize(address initialOwner, address initialController) external initializer {
        owner = initialOwner;
        controller = initialController;
    }
}
