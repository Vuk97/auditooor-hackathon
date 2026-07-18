// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILido {
    function getTotalPooledEther() external view returns (uint256);
    function getPooledEthByShares(uint256) external view returns (uint256);
}

contract LidoClean {
    ILido public lido;
    mapping(address => uint256) public sharesOf;
    function withdrawByShares(uint256 shares) external returns (uint256) {
        uint256 _balanceBefore = address(this).balance;
        uint256 _expected = lido.getPooledEthByShares(shares);
        sharesOf[msg.sender] -= shares;
        uint256 actualReceived = address(this).balance - _balanceBefore;
        require(actualReceived >= _expected * 999 / 1000, "under");
        return actualReceived;
    }
    receive() external payable {}
}
