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

// CLEAN: same WrappedCollateral shape as the vuln, but exposes an
// owner-gated `sweep(address token, address to, uint256 amount)` that
// can rescue any stray ERC20 that arrives at address(this) outside the
// wrap path. The presence of any function in the
// sweep/rescue/recoverERC20/emergencyWithdraw family is sufficient to
// suppress the detector.
contract WrappedCollateralClean {
    address public owner;
    IERC20 public underlying;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    event Sweep(address indexed token, address indexed to, uint256 amount);

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

    function wrap(address _to, uint256 _amount) external {
        SafeERC20.safeTransfer(underlying, address(this), _amount);
        _mint(_to, _amount);
    }

    function unwrap(address _to, uint256 _amount) external {
        _burn(msg.sender, _amount);
        SafeERC20.safeTransfer(underlying, _to, _amount);
    }

    /// Admin recovery for stray ERC20s. Restricted to non-underlying
    /// tokens to prevent draining the principal backing.
    function sweep(address token, address to, uint256 amount) external onlyOwner {
        require(token != address(underlying), "cannot sweep underlying");
        require(to != address(0), "zero recipient");
        SafeERC20.safeTransfer(IERC20(token), to, amount);
        emit Sweep(token, to, amount);
    }
}
