// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: setters write an address parameter into storage without any
// zero-address validation.
contract InputMissingZeroAddressCheckVuln {
    address public owner;
    address public oracle;
    address public treasury;
    address public router;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // VULN: no require(newOwner != address(0))
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    // VULN: no guard; setting oracle to address(0) silently bricks pricing.
    function setOracle(address newOracle) external onlyOwner {
        oracle = newOracle;
    }

    // VULN: init path with no zero-address guard either.
    function initialize(address _treasury) external {
        require(treasury == address(0), "already init");
        treasury = _treasury;
    }

    // VULN: update path — same class.
    function updateRouter(address _router) external onlyOwner {
        router = _router;
    }

    // VULN: configure path stores into storage without a check.
    function configureFeeRecipient(address _recipient) external onlyOwner {
        treasury = _recipient;
    }
}
