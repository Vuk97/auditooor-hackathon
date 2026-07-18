// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the
/// vulnerable fixture, but a `supportedTokens[...]` allowlist gate is
/// enforced before any transferFrom call. Unknown tokens revert.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract BridgeTokenAllowlistClean {
    mapping(address => mapping(address => uint256)) public balanceOf;
    mapping(address => bool) public supportedTokens;
    address public admin;

    constructor(address _admin) {
        admin = _admin;
    }

    function setSupported(address token, bool ok) external {
        require(msg.sender == admin, "not admin");
        supportedTokens[token] = ok;
    }

    function _handleBridge(address, address, uint256) internal pure {
        // precondition-regex trigger (same as vuln fixture)
    }

    function receiveTokens(
        address token,
        address from,
        address to,
        uint256 amount
    ) external {
        require(supportedTokens[token], "token not allowlisted");
        IERC20(token).transferFrom(from, address(this), amount);
        balanceOf[token][to] += amount;
    }
}
