// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract UUPSUpgradeable {
    address internal _implementation;

    modifier onlyOwner() {
        require(msg.sender == _owner(), "not owner");
        _;
    }

    function _owner() internal view virtual returns (address);
    function _authorizeUpgrade(address newImpl) internal virtual;
}

interface IUUPSUpgradeable {
    function proxiableUUID() external view returns (bytes32);
}

// CLEAN: both `_authorizeUpgrade` and `upgradeTo` validate that newImpl
// exposes the UUPS interface (proxiableUUID via IUUPSUpgradeable) and
// that it has contract code (newImpl.code.length > 0). An admin mis-
// configuration that points at an EOA or at a non-UUPS contract now
// reverts instead of bricking the proxy.
contract VaultProxyValidated is UUPSUpgradeable {
    address public admin;
    bytes32 internal constant _IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor() {
        admin = msg.sender;
    }

    function _owner() internal view override returns (address) {
        return admin;
    }

    function _authorizeUpgrade(address newImpl) internal override onlyOwner {
        require(newImpl.code.length > 0, "impl: not a contract");
        // IUUPSUpgradeable probe: the new impl must declare the same
        // implementation slot as this proxy, which is what an ERC-1822
        // / UUPS-compliant implementation returns from proxiableUUID.
        bytes32 slot = IUUPSUpgradeable(newImpl).proxiableUUID();
        require(slot == _IMPL_SLOT, "impl: not UUPS");
    }

    function upgradeTo(address newImpl) external onlyOwner {
        require(newImpl.code.length > 0, "impl: not a contract");
        bytes32 slot = IUUPSUpgradeable(newImpl).proxiableUUID();
        require(slot == _IMPL_SLOT, "impl: not UUPS");
        _implementation = newImpl;
    }

    function upgradeToAndCall(address newImpl, bytes calldata data)
        external
        payable
        onlyOwner
    {
        require(newImpl.code.length > 0, "impl: not a contract");
        bytes32 slot = IUUPSUpgradeable(newImpl).proxiableUUID();
        require(slot == _IMPL_SLOT, "impl: not UUPS");
        _implementation = newImpl;
        if (data.length > 0) {
            (bool ok, ) = newImpl.delegatecall(data);
            require(ok, "init failed");
        }
    }
}
