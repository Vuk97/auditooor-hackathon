// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: clones read rate=0; deposit() will divide by zero.
library Clones {
    function clone(address) internal pure returns (address) { return address(0); }
}

contract CloneConstantsUninitializedVuln {
    uint256 public rate = 1e18;
    uint256 public feeBps = 50;
    address public asset;

    function initialize(address _asset) external {
        // BUG: does not re-set rate / feeBps. Clones see 0.
        asset = _asset;
    }

    function deposit(uint256 amount) external view returns (uint256 shares) {
        shares = amount * 1e18 / rate; // divide by zero in clones
    }

    function deploy() external returns (address) {
        return Clones.clone(address(this));
    }
}
