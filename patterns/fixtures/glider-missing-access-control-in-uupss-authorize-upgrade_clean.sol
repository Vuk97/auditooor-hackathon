// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Mirrors CollateralToken.sol:249 — UUPS hook gated by `onlyOwner`.
// Detector must NOT fire on this shape.
abstract contract UUPSUpgradeable {
    function proxiableUUID() external view virtual returns (bytes32);
}

abstract contract Ownable {
    address internal _owner;
    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }
}

contract GliderMissingAccessControlInUupssAuthorizeUpgradeClean is UUPSUpgradeable, Ownable {
    function proxiableUUID() external pure override returns (bytes32) {
        return bytes32(0);
    }

    // SAFE: gated by onlyOwner — same shape as CollateralToken.sol:249.
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
