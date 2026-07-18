// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UrnAccountingVatClean {
    uint256 public Art;
    uint256 public ink;
    uint256 public spot;
    uint256 public rate;

    constructor() {
        ink = 150 ether;
        Art = 100 ether;
        spot = 1 ether;
        rate = 1 ether;
    }

    function adjustUrn(uint256 dink, uint256 dart) external {
        ink -= dink;
        Art += dart;
        require(ink * spot >= Art * rate, "unsafe-urn");
    }
}
