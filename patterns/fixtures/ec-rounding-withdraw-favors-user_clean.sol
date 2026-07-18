// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: withdraw uses ceiling division (mulDivUp) per ERC-4626 spec
contract VaultClean {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    // mulDivUp: (a * b + d - 1) / d  where d = totalAssets
    function _mulDivUp(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) {
        return (a * b + d - 1) / d;
    }

    function deposit(uint256 assets) external {
        uint256 shares = totalSupply == 0 ? assets :
            assets * totalSupply / totalAssets; // round down on deposit — correct
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        totalAssets += assets;
    }

    // CLEAN: ceiling division — vault never pays out more than fair share
    function withdraw(uint256 assets) external {
        uint256 shares = _mulDivUp(assets, totalSupply, totalAssets); // rounds UP
        require(balanceOf[msg.sender] >= shares, "insufficient shares");
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;
    }
}
