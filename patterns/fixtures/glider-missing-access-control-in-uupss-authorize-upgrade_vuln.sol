// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal UUPS shape — detector only needs to see the hook name and
// a UUPS-shaped contract source. No gating modifier, no inline check.
abstract contract UUPSUpgradeable {
    function proxiableUUID() external view virtual returns (bytes32);
}

contract GliderMissingAccessControlInUupssAuthorizeUpgradeVuln is UUPSUpgradeable {
    function proxiableUUID() external pure override returns (bytes32) {
        return bytes32(0);
    }

    // VULNERABLE: anyone can authorize an upgrade.
    function _authorizeUpgrade(address) internal {}
}
