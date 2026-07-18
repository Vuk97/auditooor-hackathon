// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice UNSEEN fixture (codex95 OBL3) for the INHERITED-ERC4626 share-price-
/// inflation surface the iter17/OBL2 detector missed.
///
/// This is the scLiquity-class shape, modelled target-literal-free with
/// deliberately different identifiers. Unlike the in-contract fixtures
/// (MiniVault / PoolVault / WrappedVault) the vault does NOT declare its own
/// `convertToShares` / `deposit(uint,address)` / `(a*b)/c` divide. Instead it:
///   (1) INHERITS a solmate-style ERC4626 base (`ERC4626`) where the public
///       deposit/mint entrypoints + the rounding-down share math live, and
///   (2) overrides ONLY `totalAssets()` to return a RAW token balance
///       (`asset.balanceOf(address(this))`), the donation-inflatable denominator.
///
/// The base has NO virtual-offset / dead-shares / minimum-first-deposit guard
/// (it is the classic pre-mitigation solmate ERC4626). A first depositor seeds
/// 1 wei -> 1 share, DONATES assets directly to the vault to inflate the live
/// totalAssets() denominator, then a later victim deposit rounds DOWN to ZERO
/// shares (its assets stay in the pool, redeemable by the attacker's 1 share).
///
/// Bug class: first-depositor / share-price inflation (donation). The detector
/// must recognize the shape from the ERC4626 inheritance + raw-balance
/// totalAssets override + absence of a guard, and drive the bug through the
/// REAL inherited `deposit()` entrypoint (reading shares via the inherited ERC20
/// `balanceOf`).

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
    function decimals() external view returns (uint8);
}

// Minimal ERC20 base providing the share-token surface (`balanceOf`, `_mint`,
// `totalSupply`). The vault's shares ARE this token.
abstract contract ERC20 {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}

// Minimal solmate-style ERC4626 base (deliberately PRE-MITIGATION: no virtual
// offset, no dead shares, no minimum first deposit). The deposit/mint public
// entrypoints + the rounding-down `convertToShares` share math live HERE, in the
// base, NOT in the vault below - which is exactly why the in-contract detector
// missed the shape. The vault IS its own ERC20 share token (`balanceOf`).
abstract contract ERC4626 is ERC20 {
    IERC20Like public immutable asset;

    constructor(IERC20Like _asset, string memory _name, string memory _symbol)
        ERC20(_name, _symbol, _asset.decimals())
    {
        asset = _asset;
    }

    function totalAssets() public view virtual returns (uint256);

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        // rounding-DOWN integer division; no virtual offset.
        return supply == 0 ? assets : (assets * supply) / totalAssets();
    }

    function deposit(uint256 assets, address receiver)
        public
        returns (uint256 shares)
    {
        shares = convertToShares(assets);
        require(
            asset.transferFrom(msg.sender, address(this), assets),
            "transfer fail"
        );
        _mint(receiver, shares);
    }

    function mint(uint256 shares, address receiver)
        public
        returns (uint256 assets)
    {
        uint256 supply = totalSupply;
        assets = supply == 0 ? shares : (shares * totalAssets()) / supply;
        require(
            asset.transferFrom(msg.sender, address(this), assets),
            "transfer fail"
        );
        _mint(receiver, shares);
    }
}

contract InheritedVault is ERC4626 {
    constructor(IERC20Like _asset)
        ERC4626(_asset, "Staked Yield", "syYLD")
    {}

    /// @dev DONATION LEVER: totalAssets() reads the LIVE vault balance, so a raw
    /// transfer into the vault inflates it without minting shares -> share price
    /// inflates and a later victim deposit rounds DOWN to zero. No virtual offset.
    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }
}
