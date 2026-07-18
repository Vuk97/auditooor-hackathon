// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC20Upgradeable {
    function transfer(address, uint256) public virtual returns (bool) {
        return true;
    }
}

contract OverrideUsesBaseQualification is ERC20Upgradeable {
    function transfer(address to, uint256 amount) public override returns (bool) {
        return ERC20Upgradeable.transfer(to, amount);
    }
}
