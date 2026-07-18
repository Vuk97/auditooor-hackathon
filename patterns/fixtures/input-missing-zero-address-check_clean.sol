// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every setter validates the address is non-zero before assigning.
contract InputMissingZeroAddressCheckClean {
    error ZeroAddress();

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

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        owner = newOwner;
    }

    function setOracle(address newOracle) external onlyOwner {
        if (newOracle == address(0)) revert ZeroAddress();
        oracle = newOracle;
    }

    function initialize(address _treasury) external {
        require(treasury == address(0), "already init");
        require(_treasury != address(0), "zero address");
        treasury = _treasury;
    }

    function updateRouter(address _router) external onlyOwner {
        require(_router != address(0), "zero address");
        router = _router;
    }

    function configureFeeRecipient(address _recipient) external onlyOwner {
        require(_recipient != address(0), "zero address");
        treasury = _recipient;
    }
}
