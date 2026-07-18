// SPDX-License-Identifier: MIT
// GAP-B+1 fixture: the cited source declares an OPEN pragma (`^0.8.0`), which on
// its own would resolve to the HIGHEST installed solc (e.g. 0.8.35). The enclosing
// foundry project, however, pins `solc = '0.8.21'` in foundry.toml. forge run
// in-place compiles under the PROJECT-PINNED solc, so the authored test pragma must
// be COMPATIBLE with 0.8.21 - pinning the test to the source-derived highest
// (0.8.35) reproduces the empirical sandclock scLiquity blocker
// `No solc version exists that matches =0.8.35`. This fixture carries ZERO target
// identity literals; the conservation shape mirrors the canonical iter17 vault.
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

contract MeridianVault {
    uint256 public trackedAssets;
    IERC20 public base;
    IERC4626 public stake;
    address public rewardSink;

    constructor(address o, IERC20 base_, IERC4626 stake_) {
        base = base_;
        stake = stake_;
    }

    function deposit(uint256 a, address r) external returns (uint256) {
        trackedAssets += a;
        return a;
    }

    function activateEpoch() external {}

    function setRewardSink(address s) external {
        rewardSink = s;
    }

    function accruedYield(address caller, uint256) public view returns (uint256) {
        if (caller == address(rewardSink)) return stake.previewRedeem(1e18);
        return 0;
    }

    function withdraw(uint256 a, address r, address o) external returns (uint256) {
        _withdraw(msg.sender, r, o, a, a);
        return a;
    }

    function _withdraw(address caller, address r, address o, uint256 assets, uint256 shares) internal {
        assets += accruedYield(caller, shares);
        trackedAssets -= assets;
    }
}
