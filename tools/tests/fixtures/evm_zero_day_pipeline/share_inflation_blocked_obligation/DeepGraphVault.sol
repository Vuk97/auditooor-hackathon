// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Step-3 fixture: a donation/share-price-inflation shape that the
/// pipeline detects but CANNOT auto-deploy generically, so it yields
/// `blocked-with-obligation` with a PRECISE next action (never a fake proof).
///
/// The bug shape is present and identical to the deployable fixture (donation-
/// inflatable `balanceOf(address(this))` denominator + rounding-down convert +
/// deposit entrypoint), but the constructor takes MULTIPLE deep-graph
/// dependencies (an asset token, a price oracle, and an access-control registry)
/// that are not a single synthesizable ERC20-asset deploy. The pipeline must
/// stop honestly and name the obligation rather than guess the extra mocks.
contract DeepGraphVault {
    IERC20 public immutable asset;
    IPriceOracle public immutable oracle;
    IRegistry public immutable registry;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(address _asset, address _oracle, address _registry) {
        asset = IERC20(_asset);
        oracle = IPriceOracle(_oracle);
        registry = IRegistry(_registry);
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets;
        }
        uint256 totalAssets = asset.balanceOf(address(this));
        return (assets * supply) / totalAssets;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 mintedShares) {
        require(registry.isAllowed(msg.sender), "not allowed");
        require(oracle.price() > 0, "stale oracle");
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

interface IPriceOracle {
    function price() external view returns (uint256);
}

interface IRegistry {
    function isAllowed(address who) external view returns (bool);
}
