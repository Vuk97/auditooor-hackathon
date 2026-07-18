// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableDiamond {
    struct FacetCut {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    mapping(bytes4 => address) public selectorToFacet;

    event DiamondCut(address indexed facet, bytes4 indexed selector);

    function diamondCut(FacetCut[] calldata cuts) external {
        _applyDiamondCut(cuts);
    }

    function _applyDiamondCut(FacetCut[] calldata cuts) internal {
        for (uint256 i = 0; i < cuts.length; i++) {
            address facet = cuts[i].facetAddress;
            for (uint256 j = 0; j < cuts[i].functionSelectors.length; j++) {
                bytes4 selector = cuts[i].functionSelectors[j];
                selectorToFacet[selector] = facet;
                emit DiamondCut(facet, selector);
            }
        }
    }
}
