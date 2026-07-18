// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILido {
    function getTotalPooledEther() external view returns (uint256);
    function getPooledEthByShares(uint256) external view returns (uint256);
}

contract LidoVuln {
    ILido public lido;
    mapping(address => uint256) public sharesOf;
    function withdrawByShares(uint256 shares) external returns (uint256) {
        uint256 eth = lido.getPooledEthByShares(shares);
        sharesOf[msg.sender] -= shares;
        return eth;
    }
}
