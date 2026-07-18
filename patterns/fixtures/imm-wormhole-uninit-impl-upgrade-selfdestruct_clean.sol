// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1822Proxiable {
    function proxiableUUID() external view returns (bytes32);
}

contract BridgeCoreClean {
    bytes32 internal constant _IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    mapping(uint256 => address) public guardianSet;
    address public implementation;
    bool private _initialized;

    constructor() {
        // Burn init slot on implementation itself.
        _initialized = true;
    }

    function initialize(address firstGuardian) external {
        require(!_initialized, "already init");
        _initialized = true;
        guardianSet[0] = firstGuardian;
    }

    function submitContractUpgrade(bytes calldata vaa, address newImpl, bytes calldata initData) external {
        require(_verifyVaa(vaa, guardianSet[0]), "bad VAA");
        // Validate the target is an actual UUPS-style contract.
        require(newImpl.code.length > 0, "EOA impl");
        require(IERC1822Proxiable(newImpl).proxiableUUID() == _IMPL_SLOT, "not proxiable");
        (bool ok, ) = newImpl.delegatecall(initData);
        require(ok, "upgrade init failed");
        implementation = newImpl;
    }

    function _verifyVaa(bytes calldata, address g) internal pure returns (bool) {
        return g != address(0);
    }
}
