// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — protocolFeeShare() no feeReceiver guard, no max cap.
// Source: euler-xyz/euler-vault-kit@52c07b3 (Cantina-207 fix)

interface IProtocolConfig {
    function protocolFeeConfig(address vault) external view returns (address receiver, uint256 share);
}

contract Governance {
    address public feeReceiver;
    IProtocolConfig public protocolConfig;
    uint256 constant CONFIG_SCALE = 1e4;
    uint256 constant MAX_PROTOCOL_FEE_SHARE = 5000; // 50%

    // VULNERABLE: does not check feeReceiver == address(0), does not cap at MAX
    function protocolFeeShare() public view returns (uint256) {
        (, uint256 protocolShare) = protocolConfig.protocolFeeConfig(address(this));
        return protocolShare;
    }
}
