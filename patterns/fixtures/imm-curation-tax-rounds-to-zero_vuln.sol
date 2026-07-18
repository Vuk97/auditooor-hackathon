// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CurationVuln {
    uint256 public constant MAX_PPM = 1000000; // parts per million
    uint256 public curationTax = 10000;         // 1%

    mapping(address => uint256) public signal;
    uint256 public totalReserve;

    // VULN: tax = tokensIn * curationTax / MAX_PPM rounds to zero for
    // tokensIn < 100 (when curationTax = 1%).
    function tokensToSignal(uint256 tokensIn) public view returns (uint256) {
        uint256 tax = (tokensIn * curationTax) / MAX_PPM;
        uint256 net = tokensIn - tax;
        return net;
    }

    function mint(uint256 tokensIn) external {
        uint256 tax = (tokensIn * curationTax) / MAX_PPM;
        uint256 net = tokensIn - tax;
        signal[msg.sender] += net;
        totalReserve += net;
    }
}
