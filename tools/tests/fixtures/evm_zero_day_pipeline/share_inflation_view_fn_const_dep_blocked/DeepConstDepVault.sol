// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice UNSEEN fixture (GAP B, honest-block half) for a const-dep-read-in-
/// view-fn vault whose deploy is TOO DEEP to auto-author, so the converter must
/// BLOCK HONESTLY (blocked-with-obligation) instead of fabricating a proof.
///
/// Modelled target-literal-free. The vault:
///   (1) reads a HARDCODED-CONSTANT external dependency (`reservePool`) INSIDE
///       the exploited `totalAssets()` view fn (the GAP B view-fn-relevant case),
///       AND
///   (2) takes a SECOND, non-asset CONTRACT-DEPENDENCY constructor arg
///       (`priceOracle`) that it CASTS and CALLS (`oracle.latestPrice()`), so the
///       ctor is NOT a single synthesizable ERC20-asset deploy: a vm.addr() EOA
///       at the oracle slot has no code and the ctor-time / view-time oracle call
///       would revert.
///
/// The GAP B view-fn const-dep detection still RECOGNIZES `reservePool` (proving
/// the new detection path fires), but the overall deploy cannot be synthesized
/// generically (the oracle dependency is out of single-asset scope), so the
/// converter returns blocked-with-obligation with a PRECISE next action - author
/// the asset + the oracle dependency mock, deploy, drive the donation sequence,
/// assert the victim is rounded to 0 shares with a no-donation negative control.
/// NO fake proof is emitted.
///
/// Bug class: first-depositor / share-price inflation (donation). Root cause is
/// the live-balance `totalAssets()` denominator; the block is purely a deploy-
/// synthesizability limit, stated honestly.
contract DeepConstDepVault {
    IERC20 public immutable asset;
    IPriceOracle public immutable priceOracle;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    /// @dev HARDCODED-CONSTANT external dependency read inside totalAssets().
    IReservePool public constant reservePool =
        IReservePool(0x6666666666666666666666666666666666666666);

    /// @dev TWO ctor args: the asset AND a non-asset contract dep (oracle). The
    /// oracle is cast + called, so it cannot be filled with a role EOA -> the
    /// single-asset auto-deploy cannot synthesize this ctor.
    constructor(address _asset, address _oracle) {
        asset = IERC20(_asset);
        priceOracle = IPriceOracle(_oracle);
    }

    function totalAssets() public view returns (uint256) {
        // const dep read in the view fn (GAP B), AND a priced reserve term that
        // depends on the oracle dependency.
        uint256 reserve = reservePool.deposited(address(this));
        uint256 priced = (reserve * priceOracle.latestPrice()) / 1e18;
        return asset.balanceOf(address(this)) + priced;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets;
        }
        return (assets * supply) / totalAssets();
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 mintedShares) {
        mintedShares = convertToShares(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer fail");
        totalShares += mintedShares;
        shares[receiver] += mintedShares;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IReservePool {
    function deposited(address vault) external view returns (uint256);
}

interface IPriceOracle {
    function latestPrice() external view returns (uint256);
}
