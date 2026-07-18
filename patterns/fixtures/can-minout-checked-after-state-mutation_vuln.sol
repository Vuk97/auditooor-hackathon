// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public totalAssets;

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    // BUG: minOut enforced AFTER _burn. Burn has already mutated state.
    function redeem(uint256 shares, uint256 minOut) external returns (uint256 out) {
        _burn(msg.sender, shares);
        out = (shares * totalAssets) / (totalSupply + shares); // uses post-burn supply
        require(out >= minOut, "slippage");
        totalAssets -= out;
        // pretend transfer happens here
    }
}
