// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC4626.sol";

/// @notice UNSEEN fixture (obl9-prep CAPABILITY 1) for the vault-conservation
/// deploy shape whose initializer takes an APPLICATION-LEVEL interface dependency
/// (`IYieldConfig`) that is NEITHER an ERC20 token NOR an ERC4626 vault. The
/// previous in-place author dropped this param at the detector and then hit the
/// `else: return None` honest-block in the author, so a real-deploy PoC could not
/// be authored even though the conservation bug is real.
///
/// The vault BOTH stores AND calls into the app-dep:
///   - `initialize(...)` calls `config_.maxYieldBps()` (reverts on a code-less
///     address, so a synthesized deployable mock is REQUIRED), and
///   - the conservation term reads `config.maxYieldBps()` again at withdraw time.
/// The app-dep synth must produce a deployable `IYieldConfig` mock with a
/// settable `maxYieldBps()` getter (settable so an exploit could drive it).
///
/// Target-literal-free: identifiers are deliberately generic (trackedAssets /
/// rewardSink / activateEpoch / base / stake / config). Bug class: accumulator
/// over-decrement (conservation): `_withdraw` decrements `trackedAssets` by
/// (base + injected ERC4626-donation yield), not base alone.
interface IYieldConfig {
    function maxYieldBps() external view returns (uint256);
}

contract AppDepVault {
    uint256 public trackedAssets;
    IERC4626 public stake;
    IYieldConfig public config;
    address public rewardSink;
    uint256 public configuredCap;

    function initialize(address o, IERC20 base, IERC4626 stake_, IYieldConfig config_)
        external
    {
        stake = stake_;
        config = config_;
        // REAL external call on the app-dep at init time: a code-less address
        // reverts here, so the synthesized deployable mock is load-bearing.
        configuredCap = config_.maxYieldBps();
    }

    function deposit(uint256 a, address r) external returns (uint256) {
        trackedAssets += a;
        return a;
    }

    function withdraw(uint256 a, address r, address o) external returns (uint256) {
        _withdraw(msg.sender, r, o, a, a);
        return a;
    }

    function setDepositsEnabled(bool v) external {}

    function setWithdrawalsEnabled(bool v) external {}

    function activateEpoch() external {}

    function setRewardSink(address s) external { rewardSink = s; }

    function accruedYield(address caller, uint256 shares) public view returns (uint256) {
        // caller-gated inflation term. The inflation does NOT depend on the
        // app-dep value (the app-dep is load-bearing for DEPLOY, via the init
        // call, not for the exploit gate), so the conservation bug fires whether
        // or not the synthesized mock's settable getter is driven.
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
