// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MakerVatDaiDebtCeilingLinePositive {
    struct Ilk {
        uint256 Art;
        uint256 rate;
        uint256 line;
    }

    mapping(bytes32 => Ilk) public ilks;
    uint256 public Line;
    uint256 public debt;

    constructor() {
        Line = 1_000_000 ether;
    }

    function seed(bytes32 ilk, uint256 art, uint256 rate, uint256 line) external {
        ilks[ilk] = Ilk({Art: art, rate: rate, line: line});
        debt = art * rate;
    }

    function fold(bytes32 ilk, uint256 rateDelta) external {
        Ilk storage i = ilks[ilk];
        i.rate += rateDelta;
        debt += i.Art * rateDelta;
    }
}
