// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the
/// vulnerable fixture, but the external `deposit` carries a
/// `nonReentrant` modifier, so any ERC-777 `tokensToSend` callback that
/// re-enters the contract reverts.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

abstract contract ReentrancyGuard {
    uint256 private _status;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "reentrant");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

contract Erc777ReceiverUncheckedReentrancyClean is ReentrancyGuard {
    mapping(address => mapping(address => uint256)) public shares;

    function deposit(address token, uint256 amount) external nonReentrant {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        shares[token][msg.sender] += amount;
    }
}
