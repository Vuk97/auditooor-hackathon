pragma solidity ^0.8.20;

contract Initializable {
    modifier initializer() {
        _;
    }
}

contract Wallet is Initializable {
    address public owner;
    address public immutable factory;

    constructor(address factory_) {
        factory = factory_;
    }

    function initialize(address initialOwner) external initializer {
        require(msg.sender == factory, "factory only");
        owner = initialOwner;
    }
}
