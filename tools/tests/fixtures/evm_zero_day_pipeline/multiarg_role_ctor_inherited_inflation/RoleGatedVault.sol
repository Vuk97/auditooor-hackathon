// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice UNSEEN fixture (codex95 OBL4 blocker 1) for the MULTI-ARG role+asset
/// constructor on an INHERITED-ERC4626 share-price-inflation vault.
///
/// Unlike the single-arg inherited fixture (InheritedVault, ctor `(IERC20Like
/// asset)`) this vault's constructor carries SEVERAL args:
///   (address admin, address keeper, ERC20Like asset, string name_, string sym_)
/// Exactly ONE arg is the deploy ASSET (the token the donation lever uses); the
/// other ADDRESS args are role/config EOAs (admin / keeper) and the string args
/// are share-token metadata. The previous author blocked any ctor with
/// len(params) != 1, so a real vault like this could not be auto-deployed.
///
/// The asset arg is forwarded into the inherited ERC4626 base ctor, so it lives
/// in the base ctor signature too; the role addresses are stored for access
/// control. The detector must (a) recognize the inherited-ERC4626 inflation
/// shape (raw-balance totalAssets override, no virtual-offset/dead-shares/min
/// guard) and (b) synthesize the multi-arg deploy: asset = synthesized token,
/// admin/keeper = distinct vm.addr() EOAs, name/symbol = literals.
///
/// Bug class: first-depositor / share-price inflation (donation). GENERIC and
/// target-literal-free; identifiers are deliberately distinct from any real
/// target.

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
    function decimals() external view returns (uint8);
}

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

// Pre-mitigation solmate-style ERC4626 base: no virtual offset, no dead shares,
// no minimum first deposit. deposit/mint + rounding-DOWN share math live here.
// The asset arg is part of the BASE ctor signature.
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

contract RoleGatedVault is ERC4626 {
    address public admin;
    address public keeper;

    // MULTI-ARG ctor: role addresses (admin, keeper) + the asset + metadata.
    // Exactly one arg (the asset) is the deploy token; admin/keeper are roles.
    constructor(
        address admin_,
        address keeper_,
        IERC20Like asset_,
        string memory name_,
        string memory symbol_
    ) ERC4626(asset_, name_, symbol_) {
        admin = admin_;
        keeper = keeper_;
    }

    /// @dev DONATION LEVER: totalAssets() reads the LIVE vault balance, so a raw
    /// transfer into the vault inflates it without minting shares. No virtual
    /// offset / dead shares / min first deposit -> first-depositor inflation.
    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }
}
