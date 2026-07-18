// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC4626.sol";

/// @notice UNSEEN fixture (obl9-prep CAPABILITY 1, honest-block half) for a
/// vault-conservation deploy shape whose app-level interface dependency is NOT
/// synthesizable: the ONLY member the target invokes on it returns a STRUCT
/// (`ConfigData`), an un-defaultable value type the protocol-dep synthesizer
/// cannot back with a safe default. The synth therefore returns None and the
/// in-place author keeps the honest block-with-obligation (it must NOT fabricate
/// a non-compiling mock, and the pipeline must NOT refute the candidate).
///
/// Target-literal-free generic identifiers. The base ERC20 + ERC4626 + phase +
/// deposit/withdraw surface is present so the deploy detector fires; the app-dep
/// is the sole un-synthesizable piece.
struct ConfigData {
    uint256 cap;
    address operator;
}

interface IRegistryView {
    function getConfig() external view returns (ConfigData memory);
}

contract UnsynthAppDepVault {
    uint256 public trackedAssets;
    IERC4626 public stake;
    IRegistryView public registry;
    address public rewardSink;

    function initialize(
        address o,
        IERC20 base,
        IERC4626 stake_,
        IRegistryView registry_
    ) external {
        stake = stake_;
        registry = registry_;
        // un-defaultable struct return -> no synthesizable mock surface.
        ConfigData memory c = registry_.getConfig();
        rewardSink = c.operator;
    }

    function deposit(uint256 a, address r) external returns (uint256) {
        trackedAssets += a;
        return a;
    }

    function withdraw(uint256 a, address r, address o) external returns (uint256) {
        _withdraw(msg.sender, r, o, a, a);
        return a;
    }

    function setWithdrawalsEnabled(bool v) external {}

    function activateEpoch() external {}

    function setRewardSink(address s) external { rewardSink = s; }

    function accruedYield(address caller, uint256 shares) public view returns (uint256) {
        if (caller == address(rewardSink)) {
            return stake.previewRedeem(1);
        }
        return 0;
    }

    function _withdraw(address caller, address r, address o, uint256 assets, uint256 shares)
        internal
    {
        assets += accruedYield(caller, shares);
        trackedAssets -= assets;
    }
}
