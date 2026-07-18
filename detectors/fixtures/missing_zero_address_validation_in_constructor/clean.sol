pragma solidity ^0.8.20;

contract MissingZeroAddressValidationInConstructorClean {
    address public owner;
    address public treasury;

    constructor(address newOwner, address newTreasury) {
        require(newOwner != address(0), "owner zero");
        require(newTreasury != address(0), "treasury zero");
        owner = newOwner;
        treasury = newTreasury;
    }
}
