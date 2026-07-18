// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC20 {
    function transfer(address, uint256) public virtual returns (bool) {
        return true;
    }

    function transferFrom(address, address, uint256) public virtual returns (bool) {
        return true;
    }
}

contract OverrideUsesSuper is ERC20 {
    function transfer(address to, uint256 amount) public override returns (bool) {
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        return super.transferFrom(from, to, amount);
    }
}
