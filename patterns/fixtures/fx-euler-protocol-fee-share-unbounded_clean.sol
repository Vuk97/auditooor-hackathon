// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — zero-receiver guard returns CONFIG_SCALE, max cap enforced.
// Source: euler-xyz/euler-vault-kit@52c07b3 (Cantina-207 fix)

interface IProtocolConfig {
    function protocolFeeConfig(address vault) external view returns (address receiver, uint256 share);
}

contract Governance {
    address public feeReceiver;
    IProtocolConfig public protocolConfig;
    uint256 constant CONFIG_SCALE = 1e4;
    uint256 constant MAX_PROTOCOL_FEE_SHARE = 5000; // 50%

    // FIXED: zero feeReceiver → burn all fees; cap at MAX_PROTOCOL_FEE_SHARE
    function protocolFeeShare() public view returns (uint256) {
        if (feeReceiver == address(0)) return CONFIG_SCALE;

        (, uint256 protocolShare) = protocolConfig.protocolFeeConfig(address(this));
        if (protocolShare > MAX_PROTOCOL_FEE_SHARE) return MAX_PROTOCOL_FEE_SHARE;

        return protocolShare;
    }
}
