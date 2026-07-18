pragma solidity ^0.8.20;

contract MissingZeroAddressValidationInConstructorPositive {
    address public owner;
    address public treasury;

    constructor(address newOwner, address newTreasury) {
        owner = newOwner;
        treasury = newTreasury;
    }
}
