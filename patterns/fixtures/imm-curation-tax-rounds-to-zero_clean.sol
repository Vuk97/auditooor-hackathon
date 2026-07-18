// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CurationClean {
    uint256 public constant MAX_PPM = 1000000;
    uint256 public curationTax = 10000; // 1%

    mapping(address => uint256) public signal;
    uint256 public totalReserve;

    // FIXED: compute net first (rounds down), derive tax as amount - net
    // (rounds up). For non-zero inputs tax is >= 1 whenever tokensIn > ~100.
    function tokensToSignal(uint256 tokensIn) public view returns (uint256) {
        uint256 net = (tokensIn * (MAX_PPM - curationTax)) / MAX_PPM;
        return net;
    }

    function mint(uint256 tokensIn) external {
        uint256 net = (tokensIn * (MAX_PPM - curationTax)) / MAX_PPM;
        uint256 tax = tokensIn - net;
        require(tax > 0 || tokensIn == 0, "dust");
        signal[msg.sender] += net;
        totalReserve += net;
    }
}
