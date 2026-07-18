// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal Wormhole-style bridge core that (a) exposes an unguarded
// initialize and (b) has a delegatecall-based contract-upgrade path
// with no validation of the newImpl target.
contract BridgeCoreVuln {
    mapping(uint256 => address) public guardianSet;
    address public implementation;
    bool public initialized; // note: never flipped back; not a real initializer

    function initialize(address firstGuardian) external {
        // No initializer modifier, no _disableInitializers burn.
        guardianSet[0] = firstGuardian;
        initialized = true;
    }

    function submitContractUpgrade(bytes calldata vaa, address newImpl, bytes calldata initData) external {
        // Pretend VAA verify: just check signer == current guardian.
        require(_verifyVaa(vaa, guardianSet[0]), "bad VAA");
        // No code.length, no proxiableUUID, no interface probe.
        // newImpl can be an EOA or a SELFDESTRUCT payload.
        (bool ok, ) = newImpl.delegatecall(initData);
        require(ok, "upgrade init failed");
        implementation = newImpl;
    }

    function _verifyVaa(bytes calldata, address g) internal pure returns (bool) {
        return g != address(0);
    }
}
