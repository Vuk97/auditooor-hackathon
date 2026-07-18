// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: contract enforces blacklist on `transfer` but forgets the same
// guard on `transferFrom` and `burn`. A blacklisted holder can still have
// their balance moved or destroyed by an approved operator.
contract BlacklistBypassTransferFromVuln {
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

    // Blacklist is enforced here …
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

    // VULN: no blacklist check on transferFrom path.
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    // VULN: burn path does not consult the blacklist either.
    function burn(address from, uint256 amt) external {
        require(msg.sender == admin, "not admin");
        balanceOf[from] -= amt;
    }

    // VULN: burnFrom — same story.
    function burnFrom(address from, uint256 amt) external {
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
    }
}
