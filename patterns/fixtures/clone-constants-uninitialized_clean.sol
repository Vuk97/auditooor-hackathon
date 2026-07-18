// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Clones {
    function clone(address) internal pure returns (address) { return address(0); }
}

contract CloneConstantsUninitializedClean {
    uint256 public rate;
    uint256 public feeBps;
    address public asset;

    function initialize(address _asset) external {
        asset = _asset;
        rate = 1e18;
        feeBps = 50;
    }

    function deposit(uint256 amount) external view returns (uint256 shares) {
        shares = amount * 1e18 / rate;
    }

    function deploy() external returns (address) {
        return Clones.clone(address(this));
    }
}
