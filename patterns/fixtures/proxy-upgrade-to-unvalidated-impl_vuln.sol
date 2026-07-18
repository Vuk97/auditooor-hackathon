// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal UUPS stand-in so the fixture compiles without node_modules.
abstract contract UUPSUpgradeable {
    address internal _implementation;

    modifier onlyOwner() {
        require(msg.sender == _owner(), "not owner");
        _;
    }

    function _owner() internal view virtual returns (address);

    // Bare _authorizeUpgrade — subclass supplies the auth rule.
    function _authorizeUpgrade(address newImpl) internal virtual;
}

// VULN: `_authorizeUpgrade` checks admin but does NOT validate that
// newImpl actually implements the UUPS surface. `upgradeTo` then blindly
// writes the implementation slot. Any admin misconfiguration (wrong
// address, phished deploy script) permanently bricks the proxy.
contract VaultProxyNoValidation is UUPSUpgradeable {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function _owner() internal view override returns (address) {
        return admin;
    }

    function _authorizeUpgrade(address newImpl) internal override onlyOwner {
        // No interface / code-length probe. Admin only.
        // Any address, including an EOA or a legacy non-UUPS contract,
        // silently passes.
    }

    function upgradeTo(address newImpl) external onlyOwner {
        _authorizeUpgrade(newImpl);
        _implementation = newImpl;
    }

    function upgradeToAndCall(address newImpl, bytes calldata data) external payable onlyOwner {
        _authorizeUpgrade(newImpl);
        _implementation = newImpl;
        if (data.length > 0) {
            (bool ok, ) = newImpl.delegatecall(data);
            require(ok, "init failed");
        }
    }
}
