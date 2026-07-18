// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: every value-moving path consults the blacklist.
contract BlacklistBypassTransferFromClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklist;

    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function setBlacklist(address a, bool b) external {
        require(msg.sender == admin, "not admin");
        blacklist[a] = b;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        require(!blacklist[msg.sender], "sender blacklisted");
        require(!blacklist[to], "to blacklisted");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function approve(address sp, uint256 amt) external returns (bool) {
        allowance[msg.sender][sp] = amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(!blacklist[from], "from blacklisted");
        require(!blacklist[to], "to blacklisted");
        require(!blacklist[msg.sender], "spender blacklisted");
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function burn(address from, uint256 amt) external {
        require(msg.sender == admin, "not admin");
        require(!blacklist[from], "from blacklisted");
        balanceOf[from] -= amt;
    }

    function burnFrom(address from, uint256 amt) external {
        require(!blacklist[from], "from blacklisted");
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
    }
}
