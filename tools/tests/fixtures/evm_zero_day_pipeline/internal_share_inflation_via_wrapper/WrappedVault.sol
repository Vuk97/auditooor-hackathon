// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Step-2 fixture: an INTERNAL vulnerable function proven THROUGH a real
/// PUBLIC wrapper. The donation/share-price-inflation bug lives in the INTERNAL
/// `_deposit` (it is internal-only and cannot be called directly), reached only
/// via the external `deposit` entrypoint. The proof pipeline's external-
/// entrypoint binder must locate `deposit` as the public caller that reaches
/// `_deposit` and drive the bug through it.
///
/// Bug class: first-depositor / share-price inflation (donation) attack.
/// Root cause: `convertToShares` uses the live vault balance as denominator, so
/// a donation inflates the share price and rounds a later victim deposit to 0.
contract WrappedVault {
    IERC20 public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets;
        }
        uint256 totalAssets = asset.balanceOf(address(this));
        return (assets * supply) / totalAssets;
    }

    /// @notice The ONLY public entrypoint. Forwards to the internal _deposit.
    function deposit(uint256 assets, address receiver) external returns (uint256) {
        return _deposit(assets, receiver);
    }

    /// @dev INTERNAL: where the vulnerable share-credit math actually runs. Not
    /// callable directly; the harness must drive it through `deposit` above.
    function _deposit(uint256 assets, address receiver) internal returns (uint256 mintedShares) {
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
