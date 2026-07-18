// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OFTVuln {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public lockUntil;

    // VULN: _transfer enforces lock but _credit (bridge-receive) does not
    function transfer(address to, uint256 amount) external returns (bool) {
        require(block.timestamp >= lockUntil[msg.sender], "locked");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function send(uint32 dstChainId, address dstRecipient, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        // emits LZ event...
    }

    function _credit(address to, uint256 amount) external {
        // VULN: no lock check on bridge-in
        balanceOf[to] += amount;
    }
}
