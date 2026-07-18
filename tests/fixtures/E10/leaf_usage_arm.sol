// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DATAFLOW-USAGE arm (net-new recall): the discriminator has a NON-canonical name
// ('route') that a fixed field-name vocabulary would miss, but dataflow shows it is
// a class SELECTOR (compared against 1 and 2). It is NOT committed to the leaf ->
// E10 fires on 'route' (enum_by=usage), which a name-only detector would silently
// miss. The domain field originNetwork is E3's cell, not E10's, and is excluded.
contract ClaimLeaf {
    function computeClaimLeaf(
        uint8 route,
        uint32 originNetwork,
        uint256 amount,
        address to
    ) internal pure returns (bytes32) {
        require(route == 1 || route == 2, "bad route");
        return keccak256(abi.encodePacked(originNetwork, amount, to));
    }
}
