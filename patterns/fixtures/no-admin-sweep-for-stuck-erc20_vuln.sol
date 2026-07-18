// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

library SafeERC20 {
    function safeTransfer(IERC20 t, address to, uint256 v) internal {
        require(t.transfer(to, v), "safeTransfer");
    }
}

// VULN: WrappedCollateral-shaped contract. User-facing wrap/unwrap pair
// custodies `underlying` 1:1 against the wrapper's own ERC20 supply, but
// the contract has NO sweep / rescue / recoverERC20 / emergencyWithdraw
// function. Any underlying token (or stray wrapper-token) sent directly
// to address(this) outside the wrap path is permanently stranded.
contract WrappedCollateralVuln {
    address public owner;
    IERC20 public underlying;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address _underlying) {
        owner = msg.sender;
        underlying = IERC20(_underlying);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    /// User-facing wrap: pulls underlying, mints wrapper 1:1.
    function wrap(address _to, uint256 _amount) external {
        SafeERC20.safeTransfer(underlying, address(this), _amount);
        _mint(_to, _amount);
    }

    /// User-facing unwrap: burns wrapper, pushes underlying 1:1.
    /// No balance-delta check; assumes `_amount` underlying still sits on
    /// address(this) untouched. Any donation past this gets first-caller-
    /// claimed but is otherwise unrecoverable.
    function unwrap(address _to, uint256 _amount) external {
        _burn(msg.sender, _amount);
        SafeERC20.safeTransfer(underlying, _to, _amount);
    }

    // NOTE: NO sweep / rescue / recoverERC20 / emergencyWithdraw.
    // Any stray ERC20 sent to address(this) is permanently stranded.
}
