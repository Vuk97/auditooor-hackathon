// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// OZ-STYLE ERC4626 base (codex95 OBL4 blocker 2b). This stands in for an
/// out-of-cited-file OpenZeppelin ERC4626 base: the public deposit/mint
/// entrypoints live HERE and dispatch into the INTERNAL `_deposit` hook that a
/// descendant overrides. The cited vault file does NOT contain this public
/// body, so the textual-call wrapper binder cannot see `deposit() -> _deposit(`.

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
        return supply == 0 ? assets : (assets * supply) / totalAssets();
    }

    // PUBLIC entrypoint -> dispatches into the internal `_deposit` HOOK that the
    // descendant overrides (OZ super.deposit() -> _deposit pattern).
    function deposit(uint256 assets, address receiver)
        public
        returns (uint256 shares)
    {
        shares = convertToShares(assets);
        _deposit(msg.sender, receiver, assets, shares);
    }

    function mint(uint256 shares, address receiver)
        public
        returns (uint256 assets)
    {
        uint256 supply = totalSupply;
        assets = supply == 0 ? shares : (shares * totalAssets()) / supply;
        _deposit(msg.sender, receiver, assets, shares);
    }

    function _deposit(
        address caller,
        address receiver,
        uint256 assets,
        uint256 shares
    ) internal virtual;
}
