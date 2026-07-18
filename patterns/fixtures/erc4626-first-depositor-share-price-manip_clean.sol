// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: ERC4626-style vault with OpenZeppelin v4.9+ style virtual-shares /
// _decimalsOffset mitigation AND a DEAD_SHARES burn on first deposit. Any
// one of these mitigations should suppress the detector's negative-guard
// regex.

interface IERC4626 {}

abstract contract ERC4626 is IERC4626 {}

contract InflationSafeVaultClean is ERC4626 {
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    uint256 public constant virtualShares = 1e6;
    uint256 public constant virtualAssets = 1;
    uint256 public constant DEAD_SHARES = 1000;
    address public constant DEAD_ADDRESS = address(0xdead);

    function _decimalsOffset() internal pure returns (uint8) {
        return 6;
    }

    // CLEAN shape 1: deposit with OZ v4.9+ virtual offsets + dead-shares
    // burn on first mint. `virtualShares`, `_decimalsOffset`, `DEAD_SHARES`,
    // and `DEAD_ADDRESS` are all present and should each independently
    // suppress the match.
    function deposit(uint256 assets) external returns (uint256 s) {
        if (totalSupply == 0) {
            s = assets - DEAD_SHARES;
            shares[DEAD_ADDRESS] += DEAD_SHARES;
            totalSupply += assets;
        } else {
            s = assets * (totalSupply + virtualShares) / (totalAssets + virtualAssets);
            require(s > 0, "zero shares");
        }
        shares[msg.sender] += s;
        totalAssets += assets;
    }

    // CLEAN shape 2: mint with initialDeposit-style gating.
    function mint(uint256 assets) external returns (uint256 s) {
        uint256 initialDeposit = 1e18;
        require(assets >= initialDeposit || totalSupply > 0, "min init");
        s = assets * (totalSupply + virtualShares) / (totalAssets + 1);
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += assets;
    }

    // CLEAN shape 3: _convertToShares with _decimalsOffset-style mitigation.
    function _convertToShares(uint256 assets) external returns (uint256 s) {
        s = assets * (totalSupply + 10 ** _decimalsOffset()) / (totalAssets + 1);
        totalSupply += s;
    }
}
